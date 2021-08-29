/*
 * Copyright 2019-2021 the original author or authors.
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

import java.util.function.Supplier;
import java.util.function.UnaryOperator;

/**
 * @author Benoit Tellier
 */
public final class ValidationUtils {

    public static final UnaryOperator<String> GENERIC_EXCEPTION_MESSAGE = objectType -> String.format("No valid %s has been provided. %s must be present, but was absent.", objectType, objectType);

    private ValidationUtils() {
    }

    public static <T> T requireNotNull(T maybeNull) {
        return requireNotNull(maybeNull, () -> new IllegalArgumentException(GENERIC_EXCEPTION_MESSAGE.apply(maybeNull.getClass().getSimpleName())));
    }

    public static <T> T requireNotNull(T maybeNull, String message) {
        return requireNotNull(maybeNull, () -> new IllegalArgumentException(message));
    }

    public static <T> T requireNotNull(T maybeNull, Supplier<RuntimeException> exceptionSupplier) {
        if (maybeNull == null) {
            throw exceptionSupplier.get();
        }
        return maybeNull;
    }
}
