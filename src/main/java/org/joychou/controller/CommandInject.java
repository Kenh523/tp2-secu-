package org.joychou.controller;

import org.joychou.security.SecurityUtil;
import org.joychou.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

@RestController
public class CommandInject {

    protected final Logger logger = LoggerFactory.getLogger(this.getClass());

    /**
     * http://localhost:8080/codeinject?filepath=/tmp;cat /etc/passwd
     *
     * @param filepath filepath
     * @return result
     */
    @GetMapping("/codeinject")
    public String codeInject(String filepath) throws IOException {

        return listDirectory(filepath);
    }

    /**
     * Host Injection
     * Host: hacked by joychou;cat /etc/passwd
     * http://localhost:8080/codeinject/host
     */
    @GetMapping("/codeinject/host")
    public String codeInjectHost(HttpServletRequest request) throws IOException {

        String host = request.getHeader("host");
        logger.info(host);
        if (host == null || !host.matches("^[A-Za-z0-9.-]{1,253}(:[0-9]{1,5})?$")) {
            return "Invalid host";
        }
        String[] cmdList = new String[]{"curl", "--max-time", "5", "--", host};
        ProcessBuilder builder = new ProcessBuilder(cmdList);
        builder.redirectErrorStream(true);
        Process process = builder.start();
        return WebUtils.convertStreamToString(process.getInputStream());
    }

    @GetMapping("/codeinject/sec")
    public String codeInjectSec(String filepath) throws IOException {
        String filterFilePath = SecurityUtil.cmdFilter(filepath);
        if (null == filterFilePath) {
            return "Bad boy. I got u.";
        }
        return listDirectory(filterFilePath);
    }

    // Liste un dossier en Java pur (aucune commande système), confiné à /tmp
    private String listDirectory(String path) throws IOException {
        java.nio.file.Path base = java.nio.file.Paths.get(System.getProperty("java.io.tmpdir")).toRealPath();
        java.nio.file.Path dir = base.resolve(path).normalize();
        if (!dir.startsWith(base) || !java.nio.file.Files.isDirectory(dir)) {
            return "Invalid directory";
        }
        StringBuilder sb = new StringBuilder();
        try (java.util.stream.Stream<java.nio.file.Path> files = java.nio.file.Files.list(dir)) {
            files.forEach(f -> sb.append(f.getFileName()).append('\n'));
        }
        return sb.toString();
    }
}
