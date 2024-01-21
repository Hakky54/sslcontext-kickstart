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
package nl.altindag.ssl;

import org.mockito.MockedStatic;
import org.mockito.stubbing.Answer;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.function.Supplier;

import static org.mockito.ArgumentMatchers.any;

/**
 * @author Hakan Altindag
 */
public final class MockUtils {

    private MockUtils() {}

    @SuppressWarnings("rawtypes")
    public static void supplyAsyncOnCurrentThread(MockedStatic<CompletableFuture> mockCompletableFuture) {
        mockCompletableFuture.when(() -> CompletableFuture.supplyAsync(any()))
                .thenAnswer((Answer<CompletableFuture<?>>) invocation -> {
                    Executor currentThread = Runnable::run;
                    Supplier<?> supplier = invocation.getArgument(0);
                    return CompletableFuture.supplyAsync(supplier, currentThread);
                });
    }

}