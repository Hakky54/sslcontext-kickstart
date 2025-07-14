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
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collector;
import java.util.stream.Collectors;

/**
 * <strong>NOTE:</strong>
 * Please don't use this class directly as it is part of the internal API. Class name and methods can be changed any time.
 *
 * @author Hakan Altindag
 */
public final class CollectorsUtils {

    private CollectorsUtils() {
    }

    public static <T> Collector<T, ?, List<T>> toUnmodifiableList() {
        return Collectors.collectingAndThen(Collectors.toList(), Collections::unmodifiableList);
    }

    public static <T> Collector<T, ?, List<T>> toModifiableList() {
        return Collectors.toCollection(ArrayList::new);
    }

    public static <T, U> Collector<Map.Entry<T, U>, ?, Map<T, U>> toModifiableMap() {
        return Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue, (previous, latest) -> latest, HashMap::new);
    }

    public static <T, U> Collector<T, ?, U> toListAndThen(Function<List<T>,U> finisher) {
        return Collectors.collectingAndThen(Collectors.toList(), finisher);
    }

    public static <T, U> Collector<Map.Entry<T, U>, ?, U> toMapAndThen(Function<Map<T, U>,U> finisher) {
        return Collectors.collectingAndThen(toModifiableMap(), finisher);
    }

    public static <T> Collector<T, ?, T[]> toArray(T[] template) {
        return Collectors.collectingAndThen(Collectors.toList(), list -> list.toArray(template));
    }

    public static Collector<String, ?, String[]> toStringArray() {
        return toArray(new String[]{});
    }

}
