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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class ValidationUtilsShould {
    static class MyException extends  RuntimeException {
        public MyException(String message) {
            super(message);
        }
    }

    @Test
    void requireNotNullNoopsWhenNotNull() {
        assertThat(ValidationUtils.requireNotNull(18, () -> new IllegalArgumentException("Custom message")))
            .isEqualTo(18);
    }

    @Test
    void requireNotNullThrowsSuppliedExceptionWhenNull() {
        assertThatThrownBy(() -> ValidationUtils.requireNotNull((Long) null, () -> new MyException("Custom message")))
            .isInstanceOf(MyException.class)
            .hasMessage("Custom message");
    }

    @Test
    void requireNotEmptyNoopsWhenNotNull() {
        assertThat(ValidationUtils.requireNotEmpty(new String[] {"Hello"}, () -> new IllegalArgumentException("Custom message")))
                .hasSize(1)
                .contains("Hello");
    }

    @Test
    void requireNotEmptyThrowsSuppliedExceptionWhenEmpty() {
        assertThatThrownBy(() -> ValidationUtils.requireNotEmpty(new String[] {}, () -> new MyException("Custom message")))
                .isInstanceOf(MyException.class)
                .hasMessage("Custom message");
    }

    @Test
    void requireNotEmptyThrowsSuppliedExceptionWhenNull() {
        assertThatThrownBy(() -> ValidationUtils.requireNotEmpty((String []) null, () -> new MyException("Custom message")))
                .isInstanceOf(MyException.class)
                .hasMessage("Custom message");
    }

}