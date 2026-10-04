import com.sun.jna.Native;
import com.sun.jna.platform.win32.Advapi32Util;
import com.sun.jna.platform.win32.Crypt32Util;
import com.sun.jna.platform.win32.WinReg;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

/**
 * 在「只保留 jlink 裁剪后的那批模块」的条件下，跑一遍 PawLocker 实际依赖的运行时能力。
 *
 * ## 为什么需要它
 *
 * Gradle 的测试是用**完整 JDK** 跑的，装进 MSI 的应用跑的是 **jlink 裁剪过的 runtime**。
 * 两者不是一回事：某个 JDK 模块被裁掉后，只有安装版会炸，而且往往炸在配对、
 * 解锁这类关键路径上——开发者本机测一辈子也遇不到。
 *
 * 尤其容易漏的是 `jdk.crypto.ec`：ECDH / ECDSA 的实现不在 `java.base` 里，
 * 而是 `jdk.crypto.ec` 提供的 Service Provider。它通过 ServiceLoader 加载，
 * `jdeps` 静态分析**看不见**这种依赖，所以 Compose 的 checkRuntime 任务也查不出来。
 * 一旦被裁，`KeyPairGenerator.getInstance("EC")` 会在运行期抛
 * NoSuchAlgorithmException，配对直接废掉。
 *
 * ## 怎么用
 *
 * 别直接跑这个类，用配套脚本——它会从实际打包出的 runtime 里读出模块清单，
 * 自动构成等价的裁剪环境：
 *
 *     tools/check-runtime-modules.sh
 *
 * 断言的范围对应 core 模块的真实用点：
 *
 * | 能力            | 用在哪                                              |
 * |-----------------|-----------------------------------------------------|
 * | JNA             | 命名管道、事件、DPAPI、注册表                        |
 * | ECDH + ECDSA    | 配对握手与解锁指令的签名                             |
 * | AES-256-GCM     | 报文机密性（含 AAD 绑定）                            |
 * | HMAC-SHA256     | HKDF 密钥派生（RFC 5869）                            |
 * | SecureRandom    | 密钥、nonce、配对码                                  |
 */
public final class RuntimeModuleCheck {

    private static int passed = 0;
    private static int failed = 0;

    /** 允许抛异常的 Runnable。 */
    @FunctionalInterface
    interface Body {
        void run() throws Exception;
    }

    private static void check(String name, Body body) {
        try {
            body.run();
            System.out.println("  [ok]   " + name);
            passed++;
        } catch (Throwable error) {
            System.out.println("  [FAIL] " + name);
            System.out.println("         " + error.getClass().getName() + ": " + error.getMessage());
            failed++;
        }
    }

    private static KeyPair ecKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom());
        return generator.generateKeyPair();
    }

    public static void main(String[] args) {
        System.out.println("JVM        : " + System.getProperty("java.version")
                + " / " + System.getProperty("java.vendor"));
        System.out.println("可见模块   : " + ModuleLayer.boot().modules().size() + " 个");
        ModuleLayer.boot().modules().stream()
                .map(Module::getName)
                .sorted()
                .forEach(name -> System.out.println("               " + name));
        System.out.println();

        check("JNA Native 加载", () -> {
            String version = Native.VERSION;
            if (version == null || version.isEmpty()) {
                throw new IllegalStateException("拿不到 JNA 版本");
            }
        });

        check("JNA Platform：DPAPI 加解密往返", () -> {
            byte[] plain = "pawlocker-dpapi-probe".getBytes(StandardCharsets.UTF_8);
            byte[] opened = Crypt32Util.cryptUnprotectData(Crypt32Util.cryptProtectData(plain));
            if (!Arrays.equals(plain, opened)) {
                throw new IllegalStateException("往返结果不一致");
            }
        });

        check("JNA Platform：读注册表（HKCU\\Environment）", () ->
                // 只读一个必然存在的值，验证 Advapi32 的注册表封装可用。
                Advapi32Util.registryGetStringValue(WinReg.HKEY_CURRENT_USER, "Environment", "TEMP"));

        check("ECDH（secp256r1）派生共享密钥", () -> {
            KeyPair a = ecKeyPair();
            KeyPair b = ecKeyPair();

            KeyAgreement ka = KeyAgreement.getInstance("ECDH");
            ka.init(a.getPrivate());
            ka.doPhase(b.getPublic(), true);
            byte[] s1 = ka.generateSecret();

            KeyAgreement kb = KeyAgreement.getInstance("ECDH");
            kb.init(b.getPrivate());
            kb.doPhase(a.getPublic(), true);
            byte[] s2 = kb.generateSecret();

            if (s1.length != 32) {
                throw new IllegalStateException("共享密钥 " + s1.length + " 字节，期望 32");
            }
            if (!Arrays.equals(s1, s2)) {
                throw new IllegalStateException("两端算出的共享密钥不一致");
            }
        });

        check("ECDSA-SHA256 签名与验签", () -> {
            KeyPair keyPair = ecKeyPair();
            byte[] message = "pawlocker".getBytes(StandardCharsets.UTF_8);

            Signature signer = Signature.getInstance("SHA256withECDSA");
            signer.initSign(keyPair.getPrivate());
            signer.update(message);
            byte[] signature = signer.sign();

            Signature verifier = Signature.getInstance("SHA256withECDSA");
            verifier.initVerify(keyPair.getPublic());
            verifier.update(message);
            if (!verifier.verify(signature)) {
                throw new IllegalStateException("验签失败");
            }
        });

        check("ECDH 公钥 X.509 编解码往返", () -> {
            KeyPair keyPair = ecKeyPair();
            byte[] encoded = keyPair.getPublic().getEncoded();
            PublicKey restored = KeyFactory.getInstance("EC")
                    .generatePublic(new X509EncodedKeySpec(encoded));
            if (!Arrays.equals(encoded, restored.getEncoded())) {
                throw new IllegalStateException("公钥往返不一致");
            }
        });

        check("AES-256-GCM 加解密（含 AAD 绑定）", () -> {
            byte[] key = new byte[32];
            new SecureRandom().nextBytes(key);
            byte[] iv = new byte[12];
            new SecureRandom().nextBytes(iv);
            byte[] aad = "PLv2|device".getBytes(StandardCharsets.UTF_8);
            byte[] plain = "unlock-payload".getBytes(StandardCharsets.UTF_8);

            Cipher encryptor = Cipher.getInstance("AES/GCM/NoPadding");
            encryptor.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(128, iv));
            encryptor.updateAAD(aad);
            byte[] ciphertext = encryptor.doFinal(plain);

            Cipher decryptor = Cipher.getInstance("AES/GCM/NoPadding");
            decryptor.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(128, iv));
            decryptor.updateAAD(aad);
            if (!Arrays.equals(plain, decryptor.doFinal(ciphertext))) {
                throw new IllegalStateException("往返不一致");
            }

            // AAD 被改动时必须解密失败。这不是可选的健壮性检查——
            // 「目标账户写进 AAD」正是绑定链的一环，AAD 校验失效等于绑定链失效。
            Cipher tampered = Cipher.getInstance("AES/GCM/NoPadding");
            tampered.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(128, iv));
            tampered.updateAAD("PLv2|other".getBytes(StandardCharsets.UTF_8));
            try {
                tampered.doFinal(ciphertext);
                throw new IllegalStateException("AAD 不匹配却解密成功了");
            } catch (AEADBadTagException expected) {
                // 正确行为
            }
        });

        check("HMAC-SHA256（HKDF 的基础）", () -> {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(new byte[32], "HmacSHA256"));
            if (mac.doFinal("salt".getBytes(StandardCharsets.UTF_8)).length != 32) {
                throw new IllegalStateException("输出长度异常");
            }
        });

        check("SHA-256 与 URL-safe Base64 往返", () -> {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest("x".getBytes(StandardCharsets.UTF_8));
            String encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
            if (!Arrays.equals(digest, Base64.getUrlDecoder().decode(encoded))) {
                throw new IllegalStateException("Base64 往返不一致");
            }
        });

        check("SecureRandom（默认强随机源）", () -> {
            SecureRandom random = new SecureRandom();
            byte[] a = new byte[32];
            byte[] b = new byte[32];
            random.nextBytes(a);
            random.nextBytes(b);
            if (Arrays.equals(a, b)) {
                throw new IllegalStateException("两次取样结果相同");
            }
            if (Arrays.equals(a, new byte[32])) {
                throw new IllegalStateException("输出全零");
            }
        });

        check("BigInteger（ECDSA 的 r/s 编解码）", () -> {
            if (new BigInteger(1, new byte[]{0x01, 0x00}).intValue() != 256) {
                throw new IllegalStateException("大数运算异常");
            }
        });

        System.out.println();
        System.out.println("结果：通过 " + passed + " 项，失败 " + failed + " 项");
        if (failed > 0) {
            System.out.println();
            System.out.println("有检查未通过 —— 说明打包出的 runtime 缺少某个必需模块。");
            System.out.println("在 windowsApp/build.gradle.kts 的 nativeDistributions 里用");
            System.out.println("modules(...) 显式补上，别去改这里的模块清单。");
            System.exit(1);
        }
    }
}
