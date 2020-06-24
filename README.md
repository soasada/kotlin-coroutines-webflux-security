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

Spring Security Webflux (like his brother the Servlet version) is all about filters, these filters are composed one after the other 
forming a chain. Every [ServerWebExchange](https://github.com/spring-projects/spring-framework/blob/master/spring-web/src/main/java/org/springframework/web/server/ServerWebExchange.java) (an exchange 
it's commonly known as an object that holds request and response, this concept exists in other places like undertow web server) has 
to go through this chain, Spring Security Webflux allow us to configure this chain ([SecurityWebFilterChain](https://github.com/spring-projects/spring-security/blob/master/web/src/main/java/org/springframework/security/web/server/SecurityWebFilterChain.java)) as we need and even 
give us the possibility to have more than one chain per path. 
The filter chain for Spring Security Webflux has the following order:

     +---------------------------+
     |                           |
     | HttpHeaderWriterWebFilter | (1)
     |                           |
     +-----------+---------------+
                 |
                 |
                 |
     +-----------v------------+
     |                        |
     | HttpsRedirectWebFilter | (2)
     |                        |
     +-----------+------------+
                 |
                 |
                 |
         +-------v-------+
         |               |
         | CorsWebFilter | (3)
         |               |
         +-------+-------+
                 |
                 |
                 |
         +-------v-------+
         |               |
         | CsrfWebFilter | (4)
         |               |
         +-------+-------+
                 |
                 |
                 |
    +------------v------------+
    |                         |
    | ReactorContextWebFilter | (5)
    |                         |
    +------------+------------+
                 |
                 |
                 |
    +------------v------------+
    |                         |
    | AuthenticationWebFilter | (6)
    |                         |
    +------------+------------+
                 |
                 |
                 |
    +------------v------------------------------+
    |                                           |
    | SecurityContextServerWebExchangeWebFilter | (7)
    |                                           |
    +------------+------------------------------+
                 |
                 |
                 |
       +---------v-------------------+
       |                             |
       | ServerRequestCacheWebFilter | (8)
       |                             |
       +---------+-------------------+
                 |
                 |
                 |
       +---------v-------+
       |                 |
       | LogoutWebFilter | (9)
       |                 |
       +---------+-------+
                 |
                 |
                 |
    +------------v------------------+
    |                               |
    | ExceptionTranslationWebFilter | (10)
    |                               |
    +------------+------------------+
                 |
                 |
                 |
    +------------v------------+
    |                         |
    |  AuthorizationWebFilter | (11)
    |                         |
    +-------------------------+
    
    - Figure 1 -

Looking at the diagram above (Figure 1), if we want to implement a JWT based security for our API (our use case in this repository), we 
have to focus on two filters: [AuthenticationWebFilter](https://github.com/spring-projects/spring-security/blob/master/web/src/main/java/org/springframework/security/web/server/authentication/AuthenticationWebFilter.java) and [AuthorizationWebFilter](https://github.com/spring-projects/spring-security/blob/master/web/src/main/java/org/springframework/security/web/server/authorization/AuthorizationWebFilter.java), but let's start with the default configuration that Spring Security Webflux give to us. 
Also, you could find the order of the filters here: [SecurityWebFiltersOrder](https://github.com/spring-projects/spring-security/blob/master/config/src/main/java/org/springframework/security/config/web/server/SecurityWebFiltersOrder.java).

### 3.1 Default Config 

Spring Security Webflux configures the filter chain automatically for us in [WebFluxSecurityConfiguration](https://github.com/spring-projects/spring-security/blob/master/config/src/main/java/org/springframework/security/config/annotation/web/reactive/WebFluxSecurityConfiguration.java#L98), through [ServerHttpSecurity](https://github.com/spring-projects/spring-security/blob/master/config/src/main/java/org/springframework/security/config/web/server/ServerHttpSecurity.java) bean, 
if we want something else we have to add this bean to our application context and explicitly configure the chain through it. 
Here you have the default config (copy and pasted from Spring Security source code):

```java
    /**
     * The default {@link ServerHttpSecurity} configuration.
     * @param http
     * @return
     */
    private SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        http
            .authorizeExchange() // this add authorization
                .anyExchange() // this method disables role based authorization
                .authenticated(); // Spring Security will authorize only authenticated users
        
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
The method shown previously (`springSecurityFilterChain`) is only executed if Spring Security does not find a 
SecurityWebFilterChain in the application context otherwise, it will load the SecurityWebFilterChain provided by us. For example, if our application has the following config (minimal one):

```kotlin
@Configuration
@EnableWebFluxSecurity
class MyWebfluxSecurityConfig
```

...and we don't have OAuth2 added as a dependency, Spring Security is going to add an http basic and form login authentication (with the famous login page)
filters for all incoming requests. But wait..., where does that `ServerHttpSecurity` bean comes from? This bean is injected by Spring Security through [ServerHttpSecurityConfiguration](https://github.com/spring-projects/spring-security/blob/master/config/src/main/java/org/springframework/security/config/annotation/web/reactive/ServerHttpSecurityConfiguration.java#L122) config class, that 
is initialized as follows (copy and pasted from Spring Security source code):

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

...so apart from the http basic and form login, we get HTTP response headers [HeaderSpec](https://github.com/spring-projects/spring-security/blob/master/config/src/main/java/org/springframework/security/config/web/server/ServerHttpSecurity.java#L3269), 
[LogoutWebFilter](https://github.com/spring-projects/spring-security/blob/master/config/src/main/java/org/springframework/security/config/web/server/ServerHttpSecurity.java#L3762) (with logout page) and 
a [ReactiveAuthenticationManager](https://github.com/spring-projects/spring-security/blob/master/core/src/main/java/org/springframework/security/authentication/ReactiveAuthenticationManager.java) specifically [UserDetailsRepositoryReactiveAuthenticationManager](https://github.com/spring-projects/spring-security/blob/master/core/src/main/java/org/springframework/security/authentication/UserDetailsRepositoryReactiveAuthenticationManager.java) that extends 
[AbstractUserDetailsReactiveAuthenticationManager](https://github.com/spring-projects/spring-security/blob/master/core/src/main/java/org/springframework/security/authentication/AbstractUserDetailsReactiveAuthenticationManager.java), if you have been working 
with Spring Security Servlet this probably sound familiar to you. 

UserDetailsRepositoryReactiveAuthenticationManager needs a bean of [ReactiveUserDetailsService](https://github.com/spring-projects/spring-security/blob/master/core/src/main/java/org/springframework/security/core/userdetails/ReactiveUserDetailsService.java) to be
able to perform the authentication (this service is used to search the user that is doing the authentication 
from database or an external service), adding a bean to your application context should do the trick, and you will have Authentication in your project.
Here you can see the final minimal configuration:

```kotlin
@Configuration
@EnableWebFluxSecurity
class MyWebfluxSecurityConfig {
    // Please don't use this on production, implement one by yourself
    @Bean
    fun userDetailsService(passwordEncoder: PasswordEncoder): MapReactiveUserDetailsService {
        return MapReactiveUserDetailsService(
            User
                .withDefaultPasswordEncoder() // deprecated
                .username("user")
                .password("user")
                .roles("USER")
                .build()
        )
    }
}
```

### 3.2 Explicit Configuration

So far so good, we saw what is doing Spring Security for us also, we know which order has the filter chain in Spring Security Webflux projects 
and what is the default configuration. At this point, we probably know that ServerHttpSecurity 
bean is used to disable, enable or setting ours filters instead of the default ones. In this section, I will explain how we can explicitly configure our chain.

Previously, I mention that simple adding a method to our configuration that adds the ServerHttpSecurity bean to our application 
context we could configure whatever we want. Imagine, we want to remove the default authentication filters, we can do it with the following code:

```kotlin
@Configuration
@EnableWebFluxSecurity
class MyWebfluxSecurityConfig {
    /*
        ServerHttpSecurity bean is injected by Spring Security, 
        see section 3.1 for knowing where comes from.
    */
    @Bean
    fun springWebFilterChain(http: ServerHttpSecurity) = http
        .httpBasic().disable()
        .formLogin().disable()
        .build()
}
```

Now if a client makes an HTTP request to our API is gonna be able to do it without problems, we 
have no security at all. As we saw in 3.1 section, the http basic and the login form authentication filters were the only
ones configured by Spring Security but, we disabled them = no authentication. 

Also, Spring Security configured by default no role based (or token based) authorization, to refresh your memory:

```java
in WebFluxSecurityConfiguration.java
...
http
    .authorizeExchange() // authorization config starts
        .anyExchange() // disables authorization
        .authenticated(); // Spring Security will authorize only authenticated users
...
``` 
 
...which means Spring Security will authorize only authenticated users but, remember we disabled authentication! then, we by pass 
the authorization filter.

Let's add some authentication and authorization to our API!

### 3.3 Authentication

Spring Security Webflux default authentication filters are (by order in the chain):

1. Http basic, see [ServerHttpSecurity:3038](https://github.com/spring-projects/spring-security/blob/master/config/src/main/java/org/springframework/security/config/web/server/ServerHttpSecurity.java#L3038)
2. Form login, see [ServerHttpSecurity:3219](https://github.com/spring-projects/spring-security/blob/master/config/src/main/java/org/springframework/security/config/web/server/ServerHttpSecurity.java#L3219)
3. OAuth2 family (in order to use this family of filters you need the `spring-boot-starter-oauth2-resource-server` dependency), see [ServerHttpSecurity:1179](https://github.com/spring-projects/spring-security/blob/master/config/src/main/java/org/springframework/security/config/web/server/ServerHttpSecurity.java#L1179)
4. Anonymous family 

(where we get the username 
and password, validate against a database/service and if success we give the user an access and refresh token)

### 3.4 Authorization

(where 
we check for every authenticated path the access token signature coming in every ServerWebExchange)

## Build project

1. Build frontend

`mvn -U clean install -pl :frontend-client`

2. Build backend

`mvn -U clean test package -pl :backend-server`

## MongoDB Index creation

Index creation must be *explicitly* enabled, since Spring Data MongoDB version 3.0, to prevent undesired effects with collection lifecyle and performance impact. In our project when we add a new `@Document` class, if this document class has any index, this index should be created manual. See [002_create_customer_collection.js](/data/mongo/002_create_customer_collection.js) for more info.

## Spring Security Webflux Authentication Flow

`LoginServerWebExchangeMatcher` > `JWTConverter` > `UserDetailsRepositoryReactiveAuthenticationManager` > `JWTServerAuthenticationSuccessHandler`