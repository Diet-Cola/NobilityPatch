package net.civex4.nobilitypatch;

import net.bytebuddy.jar.asm.ClassVisitor;
import net.bytebuddy.jar.asm.Label;
import net.bytebuddy.jar.asm.MethodVisitor;
import net.bytebuddy.jar.asm.Opcodes;

public class TestTransformer {
    public static void apply() {
        NobilityPatch.transform("net.minecraft.server.v1_16_R3.World", visitor -> new ClassVisitor(Opcodes.ASM9, visitor) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
                if ("a".equals(name) && "(Lnet/minecraft/server/v1_16_R3/BlockPosition;Lnet/minecraft/server/v1_16_R3/IBlockData;II)Z".equals(descriptor)) {
                    return new MethodVisitor(Opcodes.ASM9, cv.visitMethod(access, name, descriptor, signature, exceptions)) {
                        private boolean firstLabel = true;
                        @Override
                        public void visitLabel(Label label) {
                            mv.visitLabel(label);
                            if (firstLabel) {
                                firstLabel = false;
                                mv.visitFieldInsn(Opcodes.GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
                                mv.visitLdcInsn("Setting a blockstate!");
                                mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/String;)V", false);
                            }
                        }
                    };
                }
                return cv.visitMethod(access, name, descriptor, signature, exceptions);
            }
        });
    }
}
