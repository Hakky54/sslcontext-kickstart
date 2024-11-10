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
package nl.altindag.ssl.util;

import nl.altindag.ssl.exception.GenericException;

import java.util.function.Supplier;

/**
 * @author Hakan Altindag
 */
@FunctionalInterface
public interface Box<T> {

    ValueHolder<T> valueHolder();

    static <T> Box<T> of(T value) {
        return () -> ValueHolder.wrap(() -> value);
    }

    default <R> Box<R> map(Function<? super T, ? extends R> mapper) {
        return () -> ValueHolder.wrap(() -> {
            final T value = valueHolder().get();

            try {
                return mapper.apply(value);
            } catch (Exception e) {
                throw new GenericException(e);
            }
        });
    }

    default T get() {
        return valueHolder().get();
    }

    @FunctionalInterface
    interface ValueHolder<T> {

        Supplier<T> valueSupplier();

        default T get() {
            return valueSupplier().get();
        }

        static <U> ValueHolder<U> wrap(Supplier<U> supplier) {
            return () -> supplier;
        }
    }

}