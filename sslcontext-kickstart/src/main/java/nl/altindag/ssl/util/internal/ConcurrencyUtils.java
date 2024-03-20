/*
 * Copyright 2019 Thunderberry.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package nl.altindag.ssl.util.internal;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Supplier;

/**
 * <strong>NOTE:</strong>
 * Please don't use this class directly as it is part of the internal API. Class name and methods can be changed any time.
 *
 * @author Hakan Altindag
 */
public final class ConcurrencyUtils {

    public static final int NUMBER_OF_THREADS = 1;

    private ConcurrencyUtils() {
    }

    public static <T> CompletableFuture<T> supplyAsync(final Supplier<T> supplier) {
        ExecutorService executorService = Executors.newFixedThreadPool(NUMBER_OF_THREADS);
        CompletableFuture<T> completableFuture = new CompletableFuture<T>() {
            @Override
            public boolean complete(T value) {
                if (isDone()) {
                    return false;
                }
                executorService.shutdownNow();
                return super.complete(value);
            }

            @Override
            public boolean completeExceptionally(Throwable ex) {
                if (isDone()) {
                    return false;
                }
                executorService.shutdownNow();
                return super.completeExceptionally(ex);
            }
        };

        executorService.submit(() -> {
            try {
                completableFuture.complete(supplier.get());
            } catch (Exception exception) {
                completableFuture.completeExceptionally(exception);
            }
        });

        return completableFuture;
    }

}
