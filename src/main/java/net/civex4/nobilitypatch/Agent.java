package net.civex4.nobilitypatch;

import java.lang.instrument.Instrumentation;
import java.util.function.Function;

public class Agent {
    private static Instrumentation instrumentation;

    @SuppressWarnings("unchecked")
    public static Function<Object[], Object>[] callbacks = new Function[0];
    public static ThreadLocal<Object[]> callbackArgumentCache = ThreadLocal.withInitial(() -> new Object[0]);

    public static void agentmain(String s, Instrumentation instrumentation) {
        Agent.instrumentation = instrumentation;
    }
}
