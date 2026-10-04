package com.kira.pawlocker.core.platform

import java.io.File
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * 凭据提供程序 DLL 的定位逻辑。
 *
 * ## 为什么这个测试值得单独存在
 *
 * 这里的错误**不会在开发期暴露**：`gradle run` 走的是「从工作目录找仓库」那条分支，
 * 打包安装后才走系统属性那条。如果属性名写错、或者 jpackage 改了布局，
 * 开发时一切正常，用户装完后看到的是「找不到 DLL」——
 * 而那正是本功能最初交付时真实发生过的事。
 *
 * 所有用例都直接调用 [DesktopWindowsRegistrar] 的真实实现，不复刻逻辑 ——
 * 复刻出来的副本只会证明「我抄对了」，证明不了「实现是对的」。
 */
class CredentialProviderLocationTest {

    private val touched = mutableListOf<File>()
    private val registrar = DesktopWindowsRegistrar()

    @AfterTest
    fun cleanup() {
        val saved = System.getProperty(RESOURCES_DIR_PROPERTY)
        if (saved == null) {
            System.clearProperty(RESOURCES_DIR_PROPERTY)
        } else {
            System.setProperty(RESOURCES_DIR_PROPERTY, saved)
        }
        touched.forEach { it.deleteRecursively() }
    }

    // ——————————————————————————————————————————————————————————————
    // 打包安装的路径
    // ——————————————————————————————————————————————————————————————

    @Test
    fun `打包安装后从系统属性定位 DLL`() {
        // 模拟 jpackage 的真实布局：<安装根>/app/resources/PawLockerProvider.dll
        val installRoot = newTempDir()
        val resources = File(installRoot, "app/resources").apply { mkdirs() }
        val dll = File(resources, DLL_NAME).apply { writeText("stub") }

        System.setProperty(RESOURCES_DIR_PROPERTY, resources.absolutePath)

        val resolved = registrar.packagedCredentialProviderDll()

        assertNotNull(resolved, "属性指向的目录里有 DLL，就应该能定位到")
        assertEquals(dll.absolutePath, resolved)
    }

    @Test
    fun `属性存在但目录里没有 DLL 时不算定位成功`() {
        val resources = newTempDir().resolve("app/resources").apply { mkdirs() }
        System.setProperty(RESOURCES_DIR_PROPERTY, resources.absolutePath)

        // 属性指向一个空目录 —— 可能是安装不完整，也可能是用户手动删了 DLL。
        // 不能因为「属性存在」就返回一个不存在的路径：那样向导会预填一个假地址，
        // 用户点「注册」才报错，错误信息说「找不到 DLL」，
        // 让人以为路径填错了，其实是文件真的不在。
        assertEquals(null, registrar.packagedCredentialProviderDll())
    }

    @Test
    fun `属性为空字符串时忽略`() {
        System.setProperty(RESOURCES_DIR_PROPERTY, "")
        assertEquals(null, registrar.packagedCredentialProviderDll())
    }

    @Test
    fun `属性未设置时返回 null（开发期场景）`() {
        System.clearProperty(RESOURCES_DIR_PROPERTY)
        assertEquals(null, registrar.packagedCredentialProviderDll())
    }

    @Test
    fun `属性指向的路径带空格也能解析`() {
        // 真实安装路径是 `C:\Program Files\PawLocker\app\resources`，含空格。
        // 这条用例挡的是「顺手做了去空格处理」这类改动 ——
        // 一旦 strip 掉，路径就整体错位，而开发机上（仓库路径不含空格）根本复现不了。
        val root = newTempDir()
        val spaced = File(root, "Program Files/PawLocker/app/resources").apply { mkdirs() }
        File(spaced, DLL_NAME).writeText("stub")

        System.setProperty(RESOURCES_DIR_PROPERTY, spaced.absolutePath)

        val resolved = registrar.packagedCredentialProviderDll()
        assertNotNull(resolved)
        assertTrue(resolved.contains("Program Files"), "路径中的空格必须原样保留")
    }

    // ——————————————————————————————————————————————————————————————
    // 与打包产物的一致性
    // ——————————————————————————————————————————————————————————————

    @Test
    fun `属性名与打包产物里的一致`() {
        // 从 MSI 解包出来的 app/PawLocker.cfg 的 [JavaOptions] 段里是这个字面量：
        //     java-options=-Dcompose.application.resources.dir=$APPDIR\resources
        // 两边必须逐字一致。这条用例存在的意义就是：谁改了常量，这里会红，
        // 逼他去核对真实产物 —— 而不是等用户装完之后才发现定位不到 DLL。
        assertEquals(
            "compose.application.resources.dir",
            DesktopWindowsRegistrar.RESOURCES_DIR_PROPERTY,
        )
    }

    @Test
    fun `DLL 文件名与打包资源目录里的一致`() {
        // 与 windowsApp/resources/windows/ 下那个文件同名。
        assertEquals("PawLockerProvider.dll", DesktopWindowsRegistrar.CREDENTIAL_PROVIDER_DLL_NAME)
    }

    // ——————————————————————————————————————————————————————————————
    // 分层退回
    // ——————————————————————————————————————————————————————————————

    @Test
    fun `打包路径优先于开发期路径`() {
        val installRoot = newTempDir()
        val resources = File(installRoot, "app/resources").apply { mkdirs() }
        File(resources, DLL_NAME).writeText("stub")
        System.setProperty(RESOURCES_DIR_PROPERTY, resources.absolutePath)

        val resolved = registrar.packagedCredentialProviderDll()
        assertNotNull(resolved)
        assertTrue(
            resolved.startsWith(installRoot.absolutePath),
            "应该优先用安装目录里的那份，而不是仓库里的构建产物",
        )
    }

    @Test
    fun `建议路径在打包环境下指向安装目录`() {
        val installRoot = newTempDir()
        val resources = File(installRoot, "app/resources").apply { mkdirs() }
        File(resources, DLL_NAME).writeText("stub")
        System.setProperty(RESOURCES_DIR_PROPERTY, resources.absolutePath)

        val suggested = registrar.suggestedCredentialProviderPath()
        assertTrue(
            suggested.startsWith(installRoot.absolutePath),
            "向导预填的路径必须指向随包装好的那份，实际得到：$suggested",
        )
        assertTrue(suggested.endsWith(DLL_NAME))
    }

    // ——————————————————————————————————————————————————————————————
    // 辅助
    // ——————————————————————————————————————————————————————————————

    private fun newTempDir(): File =
        File.createTempFile("pl-loc-", "").let {
            it.delete()
            it.mkdirs()
            touched += it
            it
        }

    private companion object {
        /** 从实现里引用，测的是「实现真正会读的那个名字」。 */
        val RESOURCES_DIR_PROPERTY = DesktopWindowsRegistrar.RESOURCES_DIR_PROPERTY
        val DLL_NAME = DesktopWindowsRegistrar.CREDENTIAL_PROVIDER_DLL_NAME
    }
}
