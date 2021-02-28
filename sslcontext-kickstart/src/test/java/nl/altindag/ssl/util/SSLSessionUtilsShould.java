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

import nl.altindag.ssl.SSLFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;
import java.time.ZonedDateTime;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * @author Hakan Altindag
 */
@ExtendWith(MockitoExtension.class)
class SSLSessionUtilsShould {

    @Test
    void invalidateCaches() {
        SSLFactory sslFactory = mock(SSLFactory.class);
        SSLContext sslContext = mock(SSLContext.class);
        SSLSessionContext clientSessionContext = mock(SSLSessionContext.class);
        SSLSessionContext serverSessionContext = mock(SSLSessionContext.class);
        SSLSession clientSession = mock(SSLSession.class);
        SSLSession serverSession = mock(SSLSession.class);

        when(sslFactory.getSslContext()).thenReturn(sslContext);
        when(sslContext.getServerSessionContext()).thenReturn(serverSessionContext);
        when(sslContext.getClientSessionContext()).thenReturn(clientSessionContext);

        when(serverSessionContext.getIds()).thenReturn(Collections.enumeration(Collections.singletonList(new byte[]{1})));
        when(serverSessionContext.getSession(any())).thenReturn(serverSession);

        when(clientSessionContext.getIds()).thenReturn(Collections.enumeration(Collections.singletonList(new byte[]{1})));
        when(clientSessionContext.getSession(any())).thenReturn(clientSession);

        SSLSessionUtils.invalidateCaches(sslFactory);

        verify(serverSession, times(1)).invalidate();
        verify(clientSession, times(1)).invalidate();
    }

    @Test
    void invalidateCachesBeforeGivenTimeStamp() {
        SSLFactory sslFactory = mock(SSLFactory.class);
        SSLContext sslContext = mock(SSLContext.class);
        SSLSessionContext clientSessionContext = mock(SSLSessionContext.class);
        SSLSessionContext serverSessionContext = mock(SSLSessionContext.class);
        SSLSession clientSession = mock(SSLSession.class);
        SSLSession serverSession = mock(SSLSession.class);

        when(sslFactory.getSslContext()).thenReturn(sslContext);
        when(sslContext.getServerSessionContext()).thenReturn(serverSessionContext);
        when(sslContext.getClientSessionContext()).thenReturn(clientSessionContext);

        when(serverSessionContext.getIds()).thenReturn(Collections.enumeration(Collections.singletonList(new byte[]{1})));
        when(serverSessionContext.getSession(any())).thenReturn(serverSession);
        when(serverSession.getCreationTime()).thenReturn(ZonedDateTime.now().minusHours(1).toInstant().toEpochMilli());

        when(clientSessionContext.getIds()).thenReturn(Collections.enumeration(Collections.singletonList(new byte[]{1})));
        when(clientSessionContext.getSession(any())).thenReturn(clientSession);
        when(clientSession.getCreationTime()).thenReturn(ZonedDateTime.now().minusHours(1).toInstant().toEpochMilli());

        SSLSessionUtils.invalidateCachesBefore(sslFactory, ZonedDateTime.now());

        verify(serverSession, times(1)).invalidate();
        verify(clientSession, times(1)).invalidate();
    }

    @Test
    void notInvalidateCachesWhenSessionTimeIsAheadOfGivenTimeStamp() {
        SSLFactory sslFactory = mock(SSLFactory.class);
        SSLContext sslContext = mock(SSLContext.class);
        SSLSessionContext clientSessionContext = mock(SSLSessionContext.class);
        SSLSessionContext serverSessionContext = mock(SSLSessionContext.class);
        SSLSession clientSession = mock(SSLSession.class);
        SSLSession serverSession = mock(SSLSession.class);

        when(sslFactory.getSslContext()).thenReturn(sslContext);
        when(sslContext.getServerSessionContext()).thenReturn(serverSessionContext);
        when(sslContext.getClientSessionContext()).thenReturn(clientSessionContext);

        when(serverSessionContext.getIds()).thenReturn(Collections.enumeration(Collections.singletonList(new byte[]{1})));
        when(serverSessionContext.getSession(any())).thenReturn(serverSession);
        when(serverSession.getCreationTime()).thenReturn(ZonedDateTime.now().plusHours(1).toInstant().toEpochMilli());

        when(clientSessionContext.getIds()).thenReturn(Collections.enumeration(Collections.singletonList(new byte[]{1})));
        when(clientSessionContext.getSession(any())).thenReturn(clientSession);
        when(clientSession.getCreationTime()).thenReturn(ZonedDateTime.now().plusHours(1).toInstant().toEpochMilli());

        SSLSessionUtils.invalidateCachesBefore(sslFactory, ZonedDateTime.now());

        verify(serverSession, times(0)).invalidate();
        verify(clientSession, times(0)).invalidate();
    }

    @Test
    void invalidateCachesAfterGivenTimeStamp() {
        SSLFactory sslFactory = mock(SSLFactory.class);
        SSLContext sslContext = mock(SSLContext.class);
        SSLSessionContext clientSessionContext = mock(SSLSessionContext.class);
        SSLSessionContext serverSessionContext = mock(SSLSessionContext.class);
        SSLSession clientSession = mock(SSLSession.class);
        SSLSession serverSession = mock(SSLSession.class);

        when(sslFactory.getSslContext()).thenReturn(sslContext);
        when(sslContext.getServerSessionContext()).thenReturn(serverSessionContext);
        when(sslContext.getClientSessionContext()).thenReturn(clientSessionContext);

        when(serverSessionContext.getIds()).thenReturn(Collections.enumeration(Collections.singletonList(new byte[]{1})));
        when(serverSessionContext.getSession(any())).thenReturn(serverSession);
        when(serverSession.getCreationTime()).thenReturn(ZonedDateTime.now().minusHours(1).toInstant().toEpochMilli());

        when(clientSessionContext.getIds()).thenReturn(Collections.enumeration(Collections.singletonList(new byte[]{1})));
        when(clientSessionContext.getSession(any())).thenReturn(clientSession);
        when(clientSession.getCreationTime()).thenReturn(ZonedDateTime.now().minusHours(1).toInstant().toEpochMilli());

        SSLSessionUtils.invalidateCachesAfter(sslFactory, ZonedDateTime.now().minusHours(2));

        verify(serverSession, times(1)).invalidate();
        verify(clientSession, times(1)).invalidate();
    }

    @Test
    void notInvalidateCachesWhenSessionTimeIsBeforeOfGivenTimeStamp() {
        SSLFactory sslFactory = mock(SSLFactory.class);
        SSLContext sslContext = mock(SSLContext.class);
        SSLSessionContext clientSessionContext = mock(SSLSessionContext.class);
        SSLSessionContext serverSessionContext = mock(SSLSessionContext.class);
        SSLSession clientSession = mock(SSLSession.class);
        SSLSession serverSession = mock(SSLSession.class);

        when(sslFactory.getSslContext()).thenReturn(sslContext);
        when(sslContext.getServerSessionContext()).thenReturn(serverSessionContext);
        when(sslContext.getClientSessionContext()).thenReturn(clientSessionContext);

        when(serverSessionContext.getIds()).thenReturn(Collections.enumeration(Collections.singletonList(new byte[]{1})));
        when(serverSessionContext.getSession(any())).thenReturn(serverSession);
        when(serverSession.getCreationTime()).thenReturn(ZonedDateTime.now().minusHours(3).toInstant().toEpochMilli());

        when(clientSessionContext.getIds()).thenReturn(Collections.enumeration(Collections.singletonList(new byte[]{1})));
        when(clientSessionContext.getSession(any())).thenReturn(clientSession);
        when(clientSession.getCreationTime()).thenReturn(ZonedDateTime.now().minusHours(3).toInstant().toEpochMilli());

        SSLSessionUtils.invalidateCachesAfter(sslFactory, ZonedDateTime.now().minusHours(2));

        verify(serverSession, times(0)).invalidate();
        verify(clientSession, times(0)).invalidate();
    }

    @Test
    void invalidateCachesBetweenGivenTimeStamp() {
        SSLFactory sslFactory = mock(SSLFactory.class);
        SSLContext sslContext = mock(SSLContext.class);
        SSLSessionContext clientSessionContext = mock(SSLSessionContext.class);
        SSLSessionContext serverSessionContext = mock(SSLSessionContext.class);
        SSLSession clientSession = mock(SSLSession.class);
        SSLSession serverSession = mock(SSLSession.class);

        when(sslFactory.getSslContext()).thenReturn(sslContext);
        when(sslContext.getServerSessionContext()).thenReturn(serverSessionContext);
        when(sslContext.getClientSessionContext()).thenReturn(clientSessionContext);

        when(serverSessionContext.getIds()).thenReturn(Collections.enumeration(Collections.singletonList(new byte[]{1})));
        when(serverSessionContext.getSession(any())).thenReturn(serverSession);
        when(serverSession.getCreationTime()).thenReturn(ZonedDateTime.now().minusHours(1).toInstant().toEpochMilli());

        when(clientSessionContext.getIds()).thenReturn(Collections.enumeration(Collections.singletonList(new byte[]{1})));
        when(clientSessionContext.getSession(any())).thenReturn(clientSession);
        when(clientSession.getCreationTime()).thenReturn(ZonedDateTime.now().minusHours(1).toInstant().toEpochMilli());

        SSLSessionUtils.invalidateCachesBetween(sslFactory, ZonedDateTime.now().minusHours(2), ZonedDateTime.now());

        verify(serverSession, times(1)).invalidate();
        verify(clientSession, times(1)).invalidate();
    }

    @Test
    void updateSessionTimeout() {
        SSLFactory sslFactory = mock(SSLFactory.class);
        SSLContext sslContext = mock(SSLContext.class);
        SSLSessionContext clientSessionContext = mock(SSLSessionContext.class);
        SSLSessionContext serverSessionContext = mock(SSLSessionContext.class);

        when(sslFactory.getSslContext()).thenReturn(sslContext);
        when(sslContext.getServerSessionContext()).thenReturn(serverSessionContext);
        when(sslContext.getClientSessionContext()).thenReturn(clientSessionContext);

        SSLSessionUtils.updateSessionTimeout(sslFactory, 10);

        verify(serverSessionContext, times(1)).setSessionTimeout(10);
        verify(clientSessionContext, times(1)).setSessionTimeout(10);
    }

    @Test
    void updateSessionCacheSize() {
        SSLFactory sslFactory = mock(SSLFactory.class);
        SSLContext sslContext = mock(SSLContext.class);
        SSLSessionContext clientSessionContext = mock(SSLSessionContext.class);
        SSLSessionContext serverSessionContext = mock(SSLSessionContext.class);

        when(sslFactory.getSslContext()).thenReturn(sslContext);
        when(sslContext.getServerSessionContext()).thenReturn(serverSessionContext);
        when(sslContext.getClientSessionContext()).thenReturn(clientSessionContext);

        SSLSessionUtils.updateSessionCacheSize(sslFactory, 1024);

        verify(serverSessionContext, times(1)).setSessionCacheSize(1024);
        verify(clientSessionContext, times(1)).setSessionCacheSize(1024);
    }

    @Test
    void throwExceptionWhenUpdateSessionTimeoutWithInvalidCacheSize() {
        SSLFactory sslFactory = mock(SSLFactory.class);
        SSLContext sslContext = mock(SSLContext.class);

        when(sslFactory.getSslContext()).thenReturn(sslContext);

        assertThatThrownBy(() -> SSLSessionUtils.updateSessionTimeout(sslFactory, -1))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Unsupported timeout has been provided. Timeout should be equal or greater than [0], but received [-1]");
    }

    @Test
    void throwExceptionWhenUpdateSessionCacheSizeWithInvalidCacheSize() {
        SSLFactory sslFactory = mock(SSLFactory.class);
        SSLContext sslContext = mock(SSLContext.class);

        when(sslFactory.getSslContext()).thenReturn(sslContext);

        assertThatThrownBy(() -> SSLSessionUtils.updateSessionCacheSize(sslFactory, -1))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Unsupported cache size has been provided. Cache size should be equal or greater than [0], but received [-1]");
    }



}
