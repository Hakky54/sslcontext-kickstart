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

/**
 * @author Hakan Altindag
 */
public final class Box<T> {

    private final T value;

    public Box(T value) {
        this.value = value;
    }

    public <U> Box<U> map(Function<? super T, ? extends U> mapper) {
        try {
            return new Box<>(mapper.apply(value));
        } catch (Exception e) {
            throw new GenericException(e);
        }
    }

    public T get() {
        return value;
    }

}
