package net.civex4.nobilitypatch;

import net.bytebuddy.jar.asm.Type;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

public class CallbackKey<T> {
    private static final AtomicInteger nextId = new AtomicInteger(0);

    private final int id;
    private final Class<? extends T> type;
    private final Method functionalMethod;

    CallbackKey(Class<? extends T> type) {
        this.id = nextId.getAndIncrement();
        this.type = type;
        List<Method> functionalMethods = new ArrayList<>();
        findFunctionalMethods(type, functionalMethods, new HashSet<>());
        if (functionalMethods.size() != 1) {
            throw new IllegalArgumentException("Type " + type + " is not a functional interface");
        }
        this.functionalMethod = functionalMethods.get(0);
    }

    private static void findFunctionalMethods(Class<?> type, List<Method> functionalMethods, Set<String> overriddenMethods) {
        for (Method method : type.getMethods()) {
            String nameAndDesc = method.getName() + Type.getMethodDescriptor(method);
            if (Modifier.isAbstract(method.getModifiers()) && !overriddenMethods.contains(nameAndDesc)) {
                functionalMethods.add(method);
            } else {
                overriddenMethods.add(nameAndDesc);
            }
        }
        for (Class<?> superinterface : type.getInterfaces()) {
            findFunctionalMethods(superinterface, functionalMethods, overriddenMethods);
        }
    }

    int getId() {
        return id;
    }

    Class<? extends T> getType() {
        return type;
    }

    Method getFunctionalMethod() {
        return functionalMethod;
    }
}
