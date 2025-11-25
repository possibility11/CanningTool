import os
import shutil
import subprocess
from pathlib import Path
from typing import List
import base64
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding


def main():
    try:
        # 1. 在当前目录新建名为ca的文件夹
        ca_dir = Path("ca") # 创建ca文件夹
        ca_dir.mkdir(exist_ok=True) #
        print("✓ 已创建ca文件夹")

        # 2. 重命名指定目录下的cer文件为client.cer
        # 请将下面的路径替换为您的实际目录路径
        source_dir = Path("/path/to/your/cert/directory")  # 请修改为实际路径

        cer_files = list(source_dir.glob("*.cer"))
        if not cer_files:
            print("未找到任何.cer文件")
            return

        # 使用第一个找到的cer文件
        source_cer = cer_files[0]
        client_cer_path = source_dir / "client.cer"

        # 如果目标文件已存在，先删除
        if client_cer_path.exists():
            client_cer_path.unlink()

        # 重命名文件
        source_cer.rename(client_cer_path)
        print(f"✓ 已将 {source_cer.name} 重命名为 client.cer")

        # 3. 获取证书ID并写入certid.txt
        cert_id = extract_certificate_id(client_cer_path)
        if cert_id:
            certid_file = Path("certid.txt")
            with open(certid_file, 'w', encoding='utf-8') as f:
                f.write(cert_id)
            print(f"✓ 已提取证书ID: {cert_id}")
        else:
            print("× 无法提取证书ID")
            return

        # 4. 通过adb pull拉取tuid.txt文件
        adb_result = subprocess.run([
            'adb', 'pull',
            '/back_up/oemdata/tuid.txt',
            str(ca_dir / "tuid.txt")
        ], capture_output=True, text=True)

        if adb_result.returncode == 0:
            print("✓ 已通过adb pull拉取tuid.txt")
        else:
            print(f"× adb pull失败: {adb_result.stderr}")

        # 5. 将client.cer和certid.txt移动到ca文件夹
        # 移动client.cer
        shutil.move(str(client_cer_path), str(ca_dir / "client.cer"))

        # 移动certid.txt
        certid_file = Path("certid.txt")
        if certid_file.exists():
            shutil.move(str(certid_file), str(ca_dir / "certid.txt"))

        print("✓ 所有文件已成功移动到ca文件夹")
        print(f"✓ 完成! ca文件夹内容: {list(ca_dir.iterdir())}")

    except Exception as e:
        print(f"× 执行过程中出错: {e}")


def split_file(input_path: str, chunk_size: int = 200) -> List[str]:
    print(f"开始拆分文件：{input_path}")
    if not os.path.exists(input_path):
        error_msg = f"文件不存在：{input_path}"
        raise FileNotFoundError(error_msg)
    chunk_prefix = os.path.join(os.path.dirname(input_path), "private_part_")
    chunk_files = []
    chunk_index = 0
    with open(input_path, "rb") as f:
        while True:
            chunk_data = f.read(chunk_size)
            if not chunk_data:
                break
            suffix = chr(97 + (chunk_index // 26)) + chr(97 + (chunk_index % 26))
            chunk_file = f"{chunk_prefix}{suffix}"
            chunk_files.append(chunk_file)
            with open(chunk_file, "wb") as cf:
                cf.write(chunk_data)
            chunk_index += 1
    print(f"文件拆分完成，生成 {len(chunk_files)} 个分片")
    return chunk_files

def encrypt_chunk(chunk_path: str, pubkey_path: str) -> str:
    print(f"开始加密分片：{os.path.basename(chunk_path)}")
    with open(pubkey_path, "rb") as f:
        try:
            pubkey = serialization.load_pem_public_key(f.read(), backend=default_backend())
        except Exception as e:
            error_msg = f"公钥文件解析失败：{str(e)}"
            print(f"ERROR - {error_msg}")
            raise

    with open(chunk_path, "rb") as f:
        chunk_data = f.read()

    encrypted_data = pubkey.encrypt(chunk_data, padding.PKCS1v15())
    enc_file = f"{chunk_path}.enc"
    with open(enc_file, "wb") as f:
        f.write(encrypted_data)
    print(f"分片加密完成：{os.path.basename(enc_file)}")
    return enc_file

def merge_enc_files(enc_files: List[str], output_path: str) -> None:
    print(f"开始合并加密文件，共 {len(enc_files)} 个分片")
    with open(output_path, "wb") as out_f:
        for ef in enc_files:
            with open(ef, "rb") as in_f:
                out_f.write(in_f.read())
    print(f"合并完成：{os.path.basename(output_path)}")

def base64_encode_file(input_path: str, output_path: str, line_length: int = 64) -> None:
    print(f"开始Base64编码：{input_path}")
    with open(input_path, "rb") as f:
        base64_bytes = base64.b64encode(f.read())
    base64_str = base64_bytes.decode("utf-8")  # bytes → str
    lines = [base64_str[i:i + line_length] for i in range(0, len(base64_str), line_length)]
    multi_line_base64 = "\n".join(lines)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(multi_line_base64)
    print(f"Base64编码完成：{os.path.basename(output_path)}")

def clean_temp_files(file_list: List[str]) -> None:
    print(f"开始清理临时文件，共 {len(file_list)} 个")
    for f in file_list:
        if os.path.exists(f):
            os.remove(f)
            print(f"已删除临时文件：{os.path.basename(f)}")

def ssl_encrypt(client_key_path: str, pubkey_path: str, output_dir: str) -> None:
    # 区分正式环境和预生产环境
    try:
        print(f"=== 开始加密流程 ===")
        chunk_files = split_file(client_key_path)
        print(f"拆分完成：生成 {len(chunk_files)} 个分片")
        enc_files = []
        for i, cf in enumerate(chunk_files, 1):
            enc_file = encrypt_chunk(cf, pubkey_path)
            enc_files.append(enc_file)
            print(f"加密分片 {i}/{len(chunk_files)}：{os.path.basename(enc_file)}")
        encrypted_bin = os.path.join(output_dir, "encrypted_file.bin")
        merge_enc_files(enc_files, encrypted_bin)
        print(f"合并完成：{os.path.basename(encrypted_bin)}")
        output_filename = f"{os.path.splitext(client_key_path)[0]}_enc.key"
        client_enc_key = os.path.join(output_dir, output_filename)
        base64_encode_file(encrypted_bin, client_enc_key)
        print(f"Base64编码完成：{output_filename}")
        clean_temp_files(chunk_files + enc_files)
        if os.path.exists(encrypted_bin):
            os.remove(encrypted_bin)
            print(f"已删除中间文件：{os.path.basename(encrypted_bin)}")
        print(f"=== 加密流程完成 ===")
    except Exception as e:
        error_msg = f"加密失败：{str(e)}"
        print(f"ERROR - {error_msg}")


def extract_certificate_id(cer_file_path):
    """
    从证书文件中提取证书ID
    注意：这是一个简化版本，实际实现可能需要根据证书格式调整
    """
    try:
        # 读取证书文件
        with open(cer_file_path, 'rb') as cert_file:
            cert_data = cert_file.read()
        #  解析证书（自动处理PEM/DER格式）
        if b"-----BEGIN CERTIFICATE-----" in cert_data:
            cert = x509.load_pem_x509_certificate(cert_data, default_backend())
        else:
            cert = x509.load_der_x509_certificate(cert_data, default_backend())
        # 获取使用者（Subject）信息
        subject = cert.subject
        # 获取使用者名称（Common Name）
        common_name = subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        if common_name:
            return common_name[0].value
    except Exception as e:
        print(f"提取证书ID时出错: {e}")
        return None


if __name__ == "__main__":
    # 在使用前请修改以下路径
    # cer_file_path = "D:/fanwen/罐装小工具/kkk/kkk/client.cer"
    # cert_id = extract_certificate_id(cer_file_path)
    # print(cert_id)
    # client_key_path = r"D:/fanwen/罐装小工具/ww/ww/input/client.key"
    # public_key = r"D:/fanwen/罐装小工具/public_key/pre_env/publickey.pem"
    # 获取当前目录
    #current_dir = os.getcwd()
    #print(current_dir)
    # ssl_encrypt(client_key_path,public_key,current_dir)
    main()