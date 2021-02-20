package net.civex4.nobilitypatch;

import com.google.common.io.ByteStreams;
import com.google.common.primitives.Primitives;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.agent.ByteBuddyAgent;
import net.bytebuddy.description.method.MethodDescription;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.dynamic.DynamicType;
import net.bytebuddy.dynamic.scaffold.InstrumentedType;
import net.bytebuddy.dynamic.scaffold.subclass.ConstructorStrategy;
import net.bytebuddy.implementation.Implementation;
import net.bytebuddy.implementation.bytecode.ByteCodeAppender;
import net.bytebuddy.implementation.bytecode.Duplication;
import net.bytebuddy.implementation.bytecode.StackManipulation;
import net.bytebuddy.implementation.bytecode.StackSize;
import net.bytebuddy.implementation.bytecode.assign.Assigner;
import net.bytebuddy.implementation.bytecode.assign.TypeCasting;
import net.bytebuddy.implementation.bytecode.assign.primitive.PrimitiveBoxingDelegate;
import net.bytebuddy.implementation.bytecode.assign.primitive.PrimitiveUnboxingDelegate;
import net.bytebuddy.implementation.bytecode.collection.ArrayAccess;
import net.bytebuddy.implementation.bytecode.constant.IntegerConstant;
import net.bytebuddy.implementation.bytecode.constant.NullConstant;
import net.bytebuddy.implementation.bytecode.member.FieldAccess;
import net.bytebuddy.implementation.bytecode.member.MethodInvocation;
import net.bytebuddy.implementation.bytecode.member.MethodReturn;
import net.bytebuddy.implementation.bytecode.member.MethodVariableAccess;
import net.bytebuddy.jar.asm.ClassReader;
import net.bytebuddy.jar.asm.ClassVisitor;
import net.bytebuddy.jar.asm.ClassWriter;
import net.bytebuddy.jar.asm.MethodVisitor;
import net.bytebuddy.jar.asm.Opcodes;
import net.bytebuddy.jar.asm.Type;
import net.bytebuddy.matcher.ElementMatchers;
import org.bukkit.Bukkit;
import org.bukkit.plugin.Plugin;
import org.bukkit.plugin.java.JavaPlugin;

import java.io.File;
import java.io.IOException;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.lang.instrument.UnmodifiableClassException;
import java.lang.management.ManagementFactory;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.ProtectionDomain;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;
import java.util.function.UnaryOperator;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import java.util.logging.Level;

// https://github.com/Devan-Kerman/GrossFabricHacks/blob/master/src/main/java/net/devtech/grossfabrichacks/instrumentation/InstrumentationApi.java
public final class NobilityPatch extends JavaPlugin {
    private static final boolean EXPORT_CLASSES = Boolean.getBoolean("nobilityPatch.debug.export");

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
        String internalName = Type.getInternalName(clazz);
        ClassFileTransformer classFileTransformer = new ClassFileTransformer() {
            @Override
            public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined,
                                    ProtectionDomain protectionDomain, byte[] classfileBuffer) {
                if (!internalName.equals(className)) {
                    return classfileBuffer;
                }
                ClassReader reader = new ClassReader(classfileBuffer);
                ClassWriter writer = new ClassWriter(0);
                ClassVisitor visitor = transformer.apply(writer);
                reader.accept(visitor, 0);
                byte[] bytes = writer.toByteArray();
                if (EXPORT_CLASSES) {
                    exportClass(className, bytes);
                }
                return bytes;
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

    public static void transformMethod(Method method, UnaryOperator<MethodVisitor> methodTransformer) {
        transformMethod(method.getDeclaringClass(), method.getName(), Type.getMethodDescriptor(method), methodTransformer);
    }

    public static void transformMethod(Class<?> clazz, String name, String desc, UnaryOperator<MethodVisitor> methodTransformer) {
        transform(clazz, visitor -> new ClassVisitor(Opcodes.ASM9, visitor) {
            boolean transformed = false;
            @Override
            public MethodVisitor visitMethod(int access, String methodName, String descriptor, String signature, String[] exceptions) {
                if (name.equals(methodName) && desc.equals(descriptor)) {
                    transformed = true;
                    return methodTransformer.apply(cv.visitMethod(access, methodName, descriptor, signature, exceptions));
                } else {
                    return cv.visitMethod(access, methodName, descriptor, signature, exceptions);
                }
            }

            @Override
            public void visitEnd() {
                if (!transformed) {
                    throw new IllegalStateException("Could not find method " + name + desc);
                }
                cv.visitEnd();
            }
        });
    }

    @SuppressWarnings("rawtypes")
    public static <T> CallbackKey<T> registerCallback(Class<T> interfaceType, T callbackInstance) {
        CallbackKey<T> key = new CallbackKey<>(interfaceType);

        try {
            Class<?> agentClass = Class.forName(AGENT_CLASS_NAME, false, Bukkit.class.getClassLoader());
            Field callbackArgumentCacheField = agentClass.getField("callbackArgumentCache");
            Object[] existingCallbackArgumentCache = (Object[]) callbackArgumentCacheField.get(null);

            Method functionalMethod = key.getFunctionalMethod();
            Class<?>[] parameterTypes = functionalMethod.getParameterTypes();

            if (parameterTypes.length > existingCallbackArgumentCache.length) {
                callbackArgumentCacheField.set(null, new Object[parameterTypes.length]);
            }

            DynamicType.Unloaded<Object> dynamicType = new ByteBuddy()
                    .subclass(Object.class, ConstructorStrategy.Default.NO_CONSTRUCTORS)
                    .implement(Function.class)
                    .name("net.civex4.nobilitypatch.callback.$NobilityPatchCallbackForwarder$" + key.getId())
                    .defineField("callback", interfaceType, Modifier.PRIVATE | Modifier.FINAL)
                    .defineConstructor(Modifier.PUBLIC).withParameters(interfaceType).intercept(new Implementation() {
                        @Override
                        public InstrumentedType prepare(InstrumentedType instrumentedType) {
                            return instrumentedType;
                        }

                        @Override
                        public ByteCodeAppender appender(Target implementationTarget) {
                            return new ByteCodeAppender.Simple(
                                    MethodVariableAccess.loadThis(),
                                    implementationTarget.invokeSuper(implementationTarget.getInstrumentedType().getSuperClass().getDeclaredMethods().filter(ElementMatchers.isDefaultConstructor()).getOnly().asSignatureToken()),
                                    MethodVariableAccess.loadThis(),
                                    MethodVariableAccess.REFERENCE.loadFrom(1),
                                    FieldAccess.forField(implementationTarget.getInstrumentedType().getDeclaredFields().getOnly()).write(),
                                    MethodReturn.VOID
                            );
                        }
                    })
                    .defineMethod("apply", Object.class, Modifier.PUBLIC).withParameters(Object.class).intercept(new Implementation() {
                        @Override
                        public InstrumentedType prepare(InstrumentedType instrumentedType) {
                            return instrumentedType;
                        }

                        @Override
                        public ByteCodeAppender appender(Target implementationTarget) {
                            List<StackManipulation> manipulations = new ArrayList<>();
                            manipulations.add(MethodVariableAccess.loadThis());
                            manipulations.add(FieldAccess.forField(implementationTarget.getInstrumentedType().getDeclaredFields().getOnly()).read());

                            if (parameterTypes.length != 0) {
                                manipulations.add(MethodVariableAccess.REFERENCE.loadFrom(1));
                                TypeDescription objectArrayType = TypeDescription.ForLoadedType.of(Object[].class);
                                manipulations.add(TypeCasting.to(objectArrayType));
                                for (int i = 0; i < parameterTypes.length; i++) {
                                    if (i != parameterTypes.length - 1) {
                                        manipulations.add(Duplication.SINGLE);
                                    }
                                    manipulations.add(IntegerConstant.forValue(i));
                                    manipulations.add(ArrayAccess.of(objectArrayType).load());
                                    if (parameterTypes[i] != Object.class) {
                                        manipulations.add(TypeCasting.to(TypeDescription.ForLoadedType.of(Primitives.wrap(parameterTypes[i]))));
                                        if (parameterTypes[i].isPrimitive()) {
                                            manipulations.add(PrimitiveUnboxingDelegate.forPrimitive(TypeDescription.ForLoadedType.of(parameterTypes[i])));
                                        }
                                    }
                                    if (i != parameterTypes.length - 1) {
                                        manipulations.add(new StackManipulation() {
                                            @Override
                                            public boolean isValid() {
                                                return true;
                                            }

                                            @Override
                                            public Size apply(MethodVisitor methodVisitor,
                                                              Context implementationContext) {
                                                methodVisitor.visitInsn(Opcodes.SWAP);
                                                return StackSize.SINGLE.toIncreasingSize();
                                            }
                                        });
                                    }
                                }
                            }
                            manipulations.add(MethodInvocation.invoke(new MethodDescription.ForLoadedMethod(functionalMethod)));
                            if (functionalMethod.getReturnType().isPrimitive()) {
                                if (functionalMethod.getReturnType() == void.class) {
                                    manipulations.add(NullConstant.INSTANCE);
                                } else {
                                    manipulations.add(PrimitiveBoxingDelegate.forPrimitive(TypeDescription.ForLoadedType.of(functionalMethod.getReturnType()))
                                            .assignBoxedTo(TypeDescription.ForLoadedType.of(Primitives.wrap(functionalMethod.getReturnType())).asGenericType(), Assigner.DEFAULT, Assigner.Typing.STATIC));
                                }
                            }
                            manipulations.add(MethodReturn.of(TypeDescription.OBJECT));

                            return new ByteCodeAppender.Simple(manipulations.toArray(new StackManipulation[0]));
                        }
                    })
                    .make();
            if (EXPORT_CLASSES) {
                exportClass(dynamicType.getTypeDescription().getInternalName(), dynamicType.getBytes());
            }
            Function callbackForwarder = (Function) dynamicType
                    .load(interfaceType.getClassLoader())
                    .getLoaded()
                    .getConstructor(interfaceType)
                    .newInstance(callbackInstance);

            Field callbacksField = agentClass.getField("callbacks");
            Function[] callbacks = (Function[]) callbacksField.get(null);
            if (key.getId() >= callbacks.length) {
                Function[] newCallbacks = new Function[key.getId() + 1];
                System.arraycopy(callbacks, 0, newCallbacks, 0, callbacks.length);
                newCallbacks[key.getId()] = callbackForwarder;
                callbacksField.set(null, newCallbacks);
            }
        } catch (ReflectiveOperationException e) {
            throw new RuntimeException("Failed to register callback", e);
        }

        return key;
    }

    public static void invokeCallback(MethodVisitor mv, CallbackKey<?> key) {
        Class<?>[] parameterTypes = key.getFunctionalMethod().getParameterTypes();
        for (int i = parameterTypes.length - 1; i >= 0; i--) {
            mv.visitFieldInsn(Opcodes.GETSTATIC, AGENT_CLASS_NAME.replace('.', '/'), "callbackArgumentCache", "[Ljava/lang/Object;");
            mv.visitInsn(Opcodes.SWAP);
            IntegerConstant.forValue(i).apply(mv, null);
            mv.visitInsn(Opcodes.SWAP);
            if (parameterTypes[i].isPrimitive()) {
                PrimitiveBoxingDelegate.forPrimitive(TypeDescription.ForLoadedType.of(parameterTypes[i]))
                        .assignBoxedTo(TypeDescription.ForLoadedType.of(Primitives.wrap(parameterTypes[i])).asGenericType(), Assigner.DEFAULT, Assigner.Typing.STATIC)
                        .apply(mv, null);
            }
            mv.visitInsn(Opcodes.AASTORE);
        }
        mv.visitFieldInsn(Opcodes.GETSTATIC, AGENT_CLASS_NAME.replace('.', '/'), "callbacks", "[Ljava/util/function/Function;");
        IntegerConstant.forValue(key.getId()).apply(mv, null);
        mv.visitInsn(Opcodes.AALOAD);
        mv.visitFieldInsn(Opcodes.GETSTATIC, AGENT_CLASS_NAME.replace('.', '/'), "callbackArgumentCache", "[Ljava/lang/Object;");
        mv.visitMethodInsn(Opcodes.INVOKEINTERFACE, "java/util/function/Function", "apply", "(Ljava/lang/Object;)Ljava/lang/Object;", true);
        Class<?> returnType = key.getFunctionalMethod().getReturnType();
        if (returnType == void.class) {
            mv.visitInsn(Opcodes.POP);
        } else if (returnType != Object.class) {
            mv.visitTypeInsn(Opcodes.CHECKCAST, returnType.isArray() ? Type.getDescriptor(returnType) : Type.getInternalName(Primitives.wrap(returnType)));
            if (returnType.isPrimitive()) {
                PrimitiveUnboxingDelegate.forPrimitive(TypeDescription.ForLoadedType.of(returnType)).apply(mv, null);
            }
        }
    }

    @Override
    public void onEnable() {
    }

    @Override
    public void onDisable() {
    }

    private static void exportClass(String internalName, byte[] bytes) {
        Plugin plugin = Bukkit.getPluginManager().getPlugin("NobilityPatch");
        assert plugin != null;
        Path basePath = plugin.getDataFolder().toPath().resolve("exportedClasses");
        int slashIndex = internalName.lastIndexOf('/');
        Path dir = slashIndex == -1 ? basePath : basePath.resolve(internalName.substring(0, slashIndex).replace('/', File.separatorChar));
        try {
            Files.createDirectories(dir);
            Files.write(dir.resolve(internalName.substring(slashIndex + 1) + ".class"), bytes);
        } catch (IOException e) {
            Bukkit.getLogger().log(Level.WARNING, "Failed to export class " + internalName, e);
        }
    }
}
