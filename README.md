# Spring Webflux + Spring Security + Kotlin Coroutines

Hi! If you are one of those people like me that, are trying to learn Spring Webflux with Kotlin and Spring Security 
this repository is for you. As you probably already know, the documentation about using Spring Security with Spring Webflux 
if very scarce and if we add Kotlin on top of that, is even more. This lack of documentation has encouraged me to do this repository, 
I will try to explain how to make a custom security configuration based in JWT with Kotlin coroutines with a "close-to-real-world" minimal example.

There are few resources over the internet explaining this topic, but most of them have incomplete or incorrect information, 
I think that this is for two reasons: a poor documentation and young technology. So even trying to do it perfectly, I'm pretty sure 
I made lot of mistakes, if you find them (in the code or in the README), please make a pull request. Together we could make a better documentation for everyone.

I'm assuming that you have some knowledge with Spring Webflux (know what Mono and Flux is), so I will skip the explanation of Webflux, 
but I'm going to shed new light on how we can work with Mono and Flux with Kotlin coroutines in an imperative way.

## 1. Stack

First things first, the stack we are gonna use is the following:

* OpenJDK 14
* Kotlin 1.3.X
* Spring Boot (Webflux + Security + Reactive Data MongoDB)
* Maven
* MongoDB 4.2 through docker
* Vue.js

If you take a look at the parent [pom.xml](/pom.xml) of the project, you will see that we are compiling to java 11 
but this project runs in a OpenJDK 14 JVM. This is because Kotlin does not support java 14 bytecode yet.

## 2. Project Structure

The project consists in two maven modules:

* `backend-server` (Spring app)
* `frontend-client` (Vue.js app)

And in two more folders:

* `.github` (CI/CD)
* `data` (MongoDB scripts to initialize the database)

## 3. Security

Spring Security Webflux (like his brother Servlet version) is all about filters, these filters are composed one after the other 
forming a chain. Every [ServerWebExchange](https://github.com/spring-projects/spring-framework/blob/master/spring-web/src/main/java/org/springframework/web/server/ServerWebExchange.java) (an exchange 
it's commonly known as an object that holds request and response, this concept exists in other places like undertow web server) has 
to go through this chain. We can configure the filter chain as we need. The filter chain for Spring Security Webflux has the following path:

     +---------------------------+
     |                           |
     | HttpHeaderWriterWebFilter |
     |                           |
     +-----------+---------------+
                 |
                 |
                 |
     +-----------v------------+
     |                        |
     | HttpsRedirectWebFilter |
     |                        |
     +-----------+------------+
                 |
                 |
                 |
         +-------v-------+
         |               |
         | CorsWebFilter |
         |               |
         +-------+-------+
                 |
                 |
                 |
         +-------v-------+
         |               |
         | CsrfWebFilter |
         |               |
         +-------+-------+
                 |
                 |
                 |
    +------------v------------+
    |                         |
    | ReactorContextWebFilter |
    |                         |
    +------------+------------+
                 |
                 |
                 |
    +------------v------------+
    |                         |
    | AuthenticationWebFilter |
    |                         |
    +------------+------------+
                 |
                 |
                 |
    +------------v------------------------------+
    |                                           |
    | SecurityContextServerWebExchangeWebFilter |
    |                                           |
    +------------+------------------------------+
                 |
                 |
                 |
       +---------v-------------------+
       |                             |
       | ServerRequestCacheWebFilter |
       |                             |
       +---------+-------------------+
                 |
                 |
                 |
       +---------v-------+
       |                 |
       | LogoutWebFilter |
       |                 |
       +---------+-------+
                 |
                 |
                 |
    +------------v------------------+
    |                               |
    | ExceptionTranslationWebFilter |
    |                               |
    +------------+------------------+
                 |
                 |
                 |
    +------------v------------+
    |                         |
    |  AuthorizationWebFilter |
    |                         |
    +-------------------------+

Looking at the diagram above, if we want to implement a JWT based security for our API (our custom security for this use case), we 
have to focus on two filters: [AuthenticationWebFilter](https://github.com/spring-projects/spring-security/blob/master/web/src/main/java/org/springframework/security/web/server/authentication/AuthenticationWebFilter.java) and [AuthorizationWebFilter](https://github.com/spring-projects/spring-security/blob/master/web/src/main/java/org/springframework/security/web/server/authorization/AuthorizationWebFilter.java). Also you could find the order of the filters here: [SecurityWebFiltersOrder](https://github.com/spring-projects/spring-security/blob/master/config/src/main/java/org/springframework/security/config/web/server/SecurityWebFiltersOrder.java).

### 3.1 Default Config 

Spring Security Webflux configures the filter chain automatically for us in [WebFluxSecurityConfiguration](https://github.com/spring-projects/spring-security/blob/master/config/src/main/java/org/springframework/security/config/annotation/web/reactive/WebFluxSecurityConfiguration.java#L98), through [ServerHttpSecurity](https://github.com/spring-projects/spring-security/blob/master/config/src/main/java/org/springframework/security/config/web/server/ServerHttpSecurity.java) bean, 
if we want something else we have to add this bean to our application context and explicitly configure it. Here you have the default config:

```java
    /**
     * The default {@link ServerHttpSecurity} configuration.
     * @param http
     * @return
     */
    private SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        http
            .authorizeExchange()
                .anyExchange().authenticated();
        
        if (isOAuth2Present && OAuth2ClasspathGuard.shouldConfigure(this.context)) {
            OAuth2ClasspathGuard.configure(this.context, http);
        } else {
            http
                .httpBasic().and()
                .formLogin();
        }
        
        SecurityWebFilterChain result = http.build();
        return result;
    }
```
For example, if our application has the following config (minimal one):

```kotlin
@Configuration
@EnableWebFluxSecurity
class MyWebfluxSecurityConfig
```

...and we don't have OAuth2 added as a dependency, Spring Security is going to add an HttpBasic and login form authentication 
filters for all incoming requests.

With ServerHttpSecurity bean we can disable, enable or setting ours filters instead of the default ones. This bean is injected by Spring Security through [ServerHttpSecurityConfiguration](https://github.com/spring-projects/spring-security/blob/master/config/src/main/java/org/springframework/security/config/annotation/web/reactive/ServerHttpSecurityConfiguration.java#L122) config class, that 
initializes it with the following config:

```java
@Bean(HTTPSECURITY_BEAN_NAME)
@Scope("prototype")
public ServerHttpSecurity httpSecurity() {
    ContextAwareServerHttpSecurity http = new ContextAwareServerHttpSecurity();
    return http
        .authenticationManager(authenticationManager())
        .headers().and()
        .logout().and();
}

private ReactiveAuthenticationManager authenticationManager() {
    if (this.authenticationManager != null) {
        return this.authenticationManager;
    }
    if (this.reactiveUserDetailsService != null) {
        UserDetailsRepositoryReactiveAuthenticationManager manager =
            new UserDetailsRepositoryReactiveAuthenticationManager(this.reactiveUserDetailsService);
        if (this.passwordEncoder != null) {
            manager.setPasswordEncoder(this.passwordEncoder);
        }
        manager.setUserDetailsPasswordService(this.userDetailsPasswordService);
        return manager;
    }
    return null;
}
```

Which means that if you create your Spring Security configuration injecting this bean:

```kotlin
@Configuration
@EnableWebFluxSecurity
class MyWebfluxSecurityConfig {

    @Bean
    fun configureSecurity(http: ServerHttpSecurity): SecurityWebFilterChain {
        return http.build()
    }
}
```

Spring Security will add only HTTP response headers [HeaderSpec](https://github.com/spring-projects/spring-security/blob/master/config/src/main/java/org/springframework/security/config/web/server/ServerHttpSecurity.java#L3269), [LogoutWebFilter](https://github.com/spring-projects/spring-security/blob/master/config/src/main/java/org/springframework/security/config/web/server/ServerHttpSecurity.java#L3762) and 
a [ReactiveAuthenticationManager](https://github.com/spring-projects/spring-security/blob/master/core/src/main/java/org/springframework/security/authentication/ReactiveAuthenticationManager.java) specifically [UserDetailsRepositoryReactiveAuthenticationManager](https://github.com/spring-projects/spring-security/blob/master/core/src/main/java/org/springframework/security/authentication/UserDetailsRepositoryReactiveAuthenticationManager.java) that extends 
[AbstractUserDetailsReactiveAuthenticationManager](https://github.com/spring-projects/spring-security/blob/master/core/src/main/java/org/springframework/security/authentication/AbstractUserDetailsReactiveAuthenticationManager.java) if you have been working with Spring Security Servlet this probably sound familiar to you. 
You will need to add to the application context a bean of [ReactiveUserDetailsService](https://github.com/spring-projects/spring-security/blob/master/core/src/main/java/org/springframework/security/core/userdetails/ReactiveUserDetailsService.java) and you will have Authentication in your project.

## 3.1 Authentication

### 3.2 Authorization

## Build project

1. Build frontend

`mvn -U clean install -pl :frontend-client`

2. Build backend

`mvn -U clean test package -pl :backend-server`

## MongoDB Index creation

Index creation must be *explicitly* enabled, since Spring Data MongoDB version 3.0, to prevent undesired effects with collection lifecyle and performance impact. In our project when we add a new `@Document` class, if this document class has any index, this index should be created manual. See [002_create_customer_collection.js](/data/mongo/002_create_customer_collection.js) for more info.

## Spring Security Webflux Authentication Flow

`LoginServerWebExchangeMatcher` > `JWTConverter` > `UserDetailsRepositoryReactiveAuthenticationManager` > `JWTServerAuthenticationSuccessHandler`