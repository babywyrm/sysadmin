Spring Boot + Spring Security
dependencies.md
Зависимости
Создаем приложение с помощью Spring Initializer с модулями:

Core
Spring Boot DevTools
Security
Spring Security
Web
Spring Web Starter
links.md
Исходные коды : https://github.com/AppLoidx/spring-security-example

pom.xml.md
?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>2.1.6.RELEASE</version>
        <relativePath/> <!-- lookup parent from repository -->
    </parent>
    <groupId>com.apploidxxx</groupId>
    <artifactId>spring-security-example</artifactId>
    <version>0.0.1-SNAPSHOT</version>
    <name>spring-security-example</name>
    <description>Demo project for Spring Boot</description>

    <properties>
        <java.version>1.8</java.version>
    </properties>

    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>

        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-devtools</artifactId>
            <scope>runtime</scope>
            <optional>true</optional>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-test</artifactId>
            <scope>test</scope>
        </dependency>
        <dependency>
            <groupId>org.springframework.security</groupId>
            <artifactId>spring-security-test</artifactId>
            <scope>test</scope>
        </dependency>
    </dependencies>

    <build>
        <plugins>
            <plugin>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-maven-plugin</artifactId>
            </plugin>
        </plugins>
    </build>

</project>
SpringBoot.md
Spring Boot
Для простого примера добавим RestController и Mappings:

package com.apploidxxx.springsecurityexample.controllers;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author Arthur Kupriyanov
 */
@RestController
public class TestController {
    @RequestMapping(value = {"/", "/index"})
    public String index() {
        return "index";
    }

    @RequestMapping("/admin")
    public String admin() {
        return "admin";
    }

    @RequestMapping("/user")
    public String user() {
        return "user";
    }

    @RequestMapping("/about")
    public String about() {
        return "about";
    }

    @RequestMapping("/login")
    public String login() {
        return "login";
    }

    @RequestMapping("/403")
    public String error403() {
        return "Error page";
    }
}
И также точку входа нашего Spring Boot приложения:

package com.apploidxxx.springsecurityexample;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class SpringSecurityExampleApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityExampleApplication.class, args);
    }

}
* если вы создавали проект с помощью Spring Initializer, то нет необходимости создавать его вручную

Теперь когда мы (будучи незарегистрированными) попытаемся получить доступ к закрытым ресурсам (/user/.. и /admin/..), то получим редирект на страницу /login

SpringSecurity.md
Spring Security
Теперь нам нужно настроить Spring Security. Для этого нам необходимо создать класс конфигурацции и наследовать его от WebSecurityConfigurerAdapter.

Создадим пакет config, в который будет размещать наши классы-конфигурации

Определим в ней следующий класс:

/**
 * @author Arthur Kupriyanov
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private AccessDeniedHandler accessDeniedHandler;

    // роль admin всегда есть доступ к /admin/**
    // роль user всегда есть доступ к /user/**
    // Наш кастомный "403 access denied" обработчик
    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http.csrf().disable()
                .authorizeRequests()
                .antMatchers("/", "/index", "/about").permitAll()
                .antMatchers("/admin/**").hasAnyRole("ADMIN")
                .antMatchers("/user/**").hasAnyRole("USER")
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .loginPage("/login")
                .permitAll()
                .and()
                .logout()
                .permitAll()
                .and()
                .exceptionHandling().accessDeniedHandler(accessDeniedHandler);
    }

    // создаем пользоватлелей, admin и user
    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {

        auth.inMemoryAuthentication()
                .withUser("user").password("password").roles("USER")
                .and()
                .withUser("admin").password("password").roles("ADMIN");
    }
}
Здесь мы определили права доступа к ресурсам по ролям:

/, /index, /aboud - эти страницы будут доступны всем
/user/** - страницы совпадающие с этим выражением (начинаются с /user/...) будут доступны пользователям с ролью USER
/admin/** - будут доступны пользователям с ролью ADMIN
configure(HttpSecurity)
Метод configure(HttpSecurity) определяет, какие URL пути должны быть защищены, а какие нет. В частности, «/» и «/home» настроены без требования к авторизации. Ко всем остальным путям должна быть произведена аутентификация.

Когда пользователь успешно войдет в систему, он будет перенаправлен на предыдущую запрашиваемую страницу, требующую авторизацию.

configureGlobal(AuthenticationManagerBuilder)
Метод configure(AuthenticationManagerBuilder), то он создает в памяти хранилище пользователей, в нашем случае их 2 user и admin

Вот этот фрагмент кода нужен чтобы правильно обработать ошибку 403 (Forbidden («запрещено (не уполномочен)»)) :

@Autowired
private AccessDeniedHandler accessDeniedHandler;
Но необходимо определить этот бин:

package com.apploidxxx.heliosbackend.handers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author Arthur Kupriyanov
 *
 * обрабатывает 403 ошибку перенаправляя в случае ее вызова на /403 страницу
 */

@Component
public class CustomAccessDeniedHandler implements AccessDeniedHandler {

    private static Logger logger = LoggerFactory.getLogger(CustomAccessDeniedHandler.class);

    @Override
    public void handle(HttpServletRequest httpServletRequest,
                       HttpServletResponse httpServletResponse,
                       AccessDeniedException e) throws IOException, ServletException {

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null){
            logger.info("User '" + auth.getName() + "' tried to access the URL: " + httpServletRequest.getRequestURI());
        }
        httpServletResponse.sendRedirect(httpServletRequest.getContextPath() + "/403");
    }
}
