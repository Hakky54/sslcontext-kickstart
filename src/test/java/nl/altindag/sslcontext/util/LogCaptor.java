package nl.altindag.sslcontext.util;

import static java.util.stream.Collectors.toList;

import java.util.List;

import org.slf4j.LoggerFactory;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;

public class LogCaptor {

    private ListAppender<ILoggingEvent> listAppender;

    private LogCaptor(Class clazz) {
        Logger logger = (Logger) LoggerFactory.getLogger(clazz);

        listAppender = new ListAppender<>();
        listAppender.start();
        logger.addAppender(listAppender);
    }

    public static LogCaptor forClass(Class clazz) {
        return new LogCaptor(clazz);
    }

    public List<String> getLogs(Level level) {
        return listAppender.list.stream()
                .filter(logEvent -> logEvent.getLevel() == level)
                .map(ILoggingEvent::getFormattedMessage)
                .collect(toList());
    }

    public List<String> getLogs() {
        return listAppender.list.stream()
                .map(ILoggingEvent::getFormattedMessage)
                .collect(toList());
    }

}
