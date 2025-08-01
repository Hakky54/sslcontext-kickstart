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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;

/**
 * <strong>NOTE:</strong>
 * Please don't use this class directly as it is part of the internal API. Class name and methods can be changed any time.
 *
 * @author Hakan Altindag
 */
public final class CollectionUtils {

    private CollectionUtils() {
    }

    public static boolean isEmpty(List<?> collection) {
        return collection == null || collection.isEmpty();
    }

    @SafeVarargs
    public static <T> List<T> toUnmodifiableList(T... values) {
        return Collections.unmodifiableList(Arrays.asList(values));
    }

    public static <T> List<T> toUnmodifiableList(Set<T> values) {
        return Collections.unmodifiableList(new ArrayList<>(values));
    }

}
