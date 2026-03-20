# SM2 固定 fixture（eet 生成）

> 实际 PEM 文件位于：`tests-api/shell/fixtures/`。

- `test_sm2_sm2_public.pem` / `test_sm2_sm2_private.pem`：由 `eet sm2 generate` 生成。
- **私钥密码**：`ApiTestPwd01`（仅用于自动化测试，勿用于生产）。

pygmssl 可 **`load_pem_private_key(pem, b"ApiTestPwd01")`** 读取该 **ENCRYPTED PRIVATE KEY**（PBES2 + PBKDF2-HMAC-SM3 + SM4-CBC）。公钥亦可用 `load_pem_public_key` 加载。`eet sm2 decrypt` / `eet sm2 sign` 仍使用本加密私钥与上述密码。
