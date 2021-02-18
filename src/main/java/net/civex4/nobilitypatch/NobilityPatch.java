package net.civex4.nobilitypatch;

import com.google.common.io.ByteStreams;
import net.bytebuddy.agent.ByteBuddyAgent;
import net.bytebuddy.jar.asm.ClassReader;
import net.bytebuddy.jar.asm.ClassVisitor;
import net.bytebuddy.jar.asm.ClassWriter;
import org.bukkit.Bukkit;
import org.bukkit.plugin.java.JavaPlugin;

import java.io.File;
import java.io.IOException;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.lang.instrument.UnmodifiableClassException;
import java.lang.management.ManagementFactory;
import java.lang.reflect.Field;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.ProtectionDomain;
import java.util.function.UnaryOperator;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import java.util.logging.Level;

// https://github.com/Devan-Kerman/GrossFabricHacks/blob/master/src/main/java/net/devtech/grossfabrichacks/instrumentation/InstrumentationApi.java
public final class NobilityPatch extends JavaPlugin {
    private static final String AGENT_CLASS_NAME = "net.civex4.nobilitypatch.Agent";

    static Instrumentation instrumentation;

    static {
        try {
            attachInstrumentation();
        } catch (IOException | ReflectiveOperationException | URISyntaxException e) {
            throw new RuntimeException("Failed to create NobilityPatch agent", e);
        }
    }

    private static void attachInstrumentation() throws IOException, ReflectiveOperationException, URISyntaxException {
        File jarFile = File.createTempFile("agent", ".jar");
        Path jarPath = jarFile.toPath();

        Bukkit.getLogger().log(Level.INFO, "Attaching instrumentation agent to VM.");

        Bukkit.getLogger().log(Level.INFO, "Agent JAR file: " + jarFile.getAbsolutePath());

        Manifest manifest = new Manifest();
        manifest.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
        manifest.getMainAttributes().put(new Attributes.Name("Agent-Class"), AGENT_CLASS_NAME);
        manifest.getMainAttributes().put(new Attributes.Name("Can-Retransform-Classes"), "true");
        manifest.getMainAttributes().put(new Attributes.Name("Can-Redefine-Classes"), "true");

        try (JarOutputStream jar = new JarOutputStream(Files.newOutputStream(jarPath), manifest);
             JarFile pluginJar = new JarFile(new File(NobilityPatch.class.getProtectionDomain().getCodeSource().getLocation().toURI()))) {
            String entryName = AGENT_CLASS_NAME.replace('.', '/') + ".class";
            jar.putNextEntry(new JarEntry(entryName));
            //noinspection UnstableApiUsage
            ByteStreams.copy(pluginJar.getInputStream(pluginJar.getJarEntry(entryName)), jar);
            jar.closeEntry();
        }

        String runtimeMXBeanName = ManagementFactory.getRuntimeMXBean().getName();
        String pid = runtimeMXBeanName.substring(0, runtimeMXBeanName.indexOf('@'));

        ByteBuddyAgent.attach(jarFile, pid);

        Bukkit.getLogger().log(Level.INFO, "Successfully attached instrumentation agent.");

        Files.delete(jarPath);

        Class<?> agentClass = Class.forName(AGENT_CLASS_NAME, false, Bukkit.class.getClassLoader());
        Field field = agentClass.getDeclaredField("instrumentation");
        field.setAccessible(true);
        instrumentation = (Instrumentation) field.get(null);
    }

    public static void transform(String className, UnaryOperator<ClassVisitor> transformer) {
        try {
            transform(Class.forName(className), transformer);
        } catch (ClassNotFoundException e) {
            throw new RuntimeException(e);
        }
    }

    public static void transform(Class<?> clazz, UnaryOperator<ClassVisitor> transformer) {
        ClassFileTransformer classFileTransformer = new ClassFileTransformer() {
            @Override
            public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined,
                                    ProtectionDomain protectionDomain, byte[] classfileBuffer) {
                ClassReader reader = new ClassReader(classfileBuffer);
                ClassWriter writer = new ClassWriter(0);
                ClassVisitor visitor = transformer.apply(writer);
                reader.accept(visitor, 0);
                return writer.toByteArray();
            }
        };
        instrumentation.addTransformer(classFileTransformer, true);
        try {
            instrumentation.retransformClasses(clazz);
        } catch (UnmodifiableClassException e) {
            Bukkit.getLogger().log(Level.SEVERE, "Could not transform unmodifiable class " + clazz.getName(), e);
        }
        instrumentation.removeTransformer(classFileTransformer);
    }

    @Override
    public void onEnable() {
        TestTransformer.apply();
    }

    @Override
    public void onDisable() {
    }
}
