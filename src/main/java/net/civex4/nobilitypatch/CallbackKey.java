package net.civex4.nobilitypatch;

import java.util.concurrent.atomic.AtomicInteger;

public class CallbackKey<T> {
    private static final AtomicInteger nextId = new AtomicInteger(0);

    private final String fieldName;
    private final Class<? extends T> type;

    CallbackKey(Class<? extends T> type) {
        this.fieldName = "nobilitypatch$callback$" + nextId.getAndIncrement();
        this.type = type;
    }

    String getFieldName() {
        return fieldName;
    }

    Class<? extends T> getType() {
        return type;
    }
}
