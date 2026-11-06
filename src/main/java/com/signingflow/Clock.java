package com.signingflow;

import java.time.Duration;
import java.time.Instant;
import java.util.function.Consumer;
import java.util.function.Supplier;

/** Time source. Tests replace {@link #now} and {@link #sleep}. */
public final class Clock {
    private static final Consumer<Duration> SLEEP = duration -> {
        if (duration == null || duration.isZero() || duration.isNegative()) {
            return;
        }
        try {
            Thread.sleep(duration.toMillis());
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        }
    };

    public static volatile Supplier<Instant> now = Instant::now;
    public static volatile Consumer<Duration> sleep = SLEEP;

    private Clock() {}

    public static Instant instant() {
        return now.get();
    }

    public static void pause(Duration duration) {
        sleep.accept(duration);
    }

    public static void reset() {
        now = Instant::now;
        sleep = SLEEP;
    }
}
