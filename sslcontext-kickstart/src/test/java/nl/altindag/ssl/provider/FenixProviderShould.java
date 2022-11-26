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
package nl.altindag.ssl.provider;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class FenixProviderShould {

    @Test
    void getInstance() {
        FenixProvider fenixProvider = FenixProvider.getInstance();

        assertThat(fenixProvider).isNotNull();
        assertThat(fenixProvider.getName()).isEqualTo("Fenix");
        assertThat(fenixProvider.getInfo()).isEqualTo("Provides various security objects");
        assertThat(fenixProvider.getVersion()).isEqualTo(1.0);

        assertThat(fenixProvider.hashCode()).isEqualTo(FenixProvider.getInstance().hashCode());
    }

}
