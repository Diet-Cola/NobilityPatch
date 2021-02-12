package net.civex4.nobilitypatch;

import java.lang.instrument.Instrumentation;

public class Agent {
    private static Instrumentation instrumentation;

    public static void agentmain(String s, Instrumentation instrumentation) {
        Agent.instrumentation = instrumentation;
    }
}
