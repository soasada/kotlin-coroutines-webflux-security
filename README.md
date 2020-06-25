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

Spring Security Webflux (like his brother the Servlet version) it's all about filters, these filters are composed one after the other 
forming a chain. Every [ServerWebExchange](https://github.com/spring-projects/spring-framework/blob/master/spring-web/src/main/java/org/springframework/web/server/ServerWebExchange.java) (an exchange 
it's commonly known as an object that holds request and response, this concept exists in other places like undertow web server) has 
to go through this chain. Spring Security Webflux allow us to configure the chain ([SecurityWebFilterChain](https://github.com/spring-projects/spring-security/blob/master/web/src/main/java/org/springframework/security/web/server/SecurityWebFilterChain.java)) as we need and even 
give us the possibility to have more than one per path. 
The filter chain for Spring Security Webflux has the following order:

     +---------------------------+
     |                           |
     | HttpHeaderWriterWebFilter | (1) default
     |                           |
     +-----------+---------------+
                 |
                 |
                 |
     +-----------v------------+
     |                        |
     | HttpsRedirectWebFilter | (2) configurable
     |                        |
     +-----------+------------+
                 |
                 |
                 |
         +-------v-------+
         |               |
         | CorsWebFilter | (3) configurable
         |               |
         +-------+-------+
                 |
                 |
                 |
         +-------v-------+
         |               |
         | CsrfWebFilter | (4) default
         |               |
         +-------+-------+
                 |
                 |
                 |
    +------------v------------+
    |                         |
    | ReactorContextWebFilter | (5) default
    |                         |
    +------------+------------+
                 |
                 |
                 |
    +------------v------------+
    |                         |
    | AuthenticationWebFilter | (6) default
    |                         |
    +------------+------------+
                 |
                 |
                 |
    +------------v------------------------------+
    |                                           |
    | SecurityContextServerWebExchangeWebFilter | (7) default
    |                                           |
    +------------+------------------------------+
                 |
                 |
                 |
       +---------v-------------------+
       |                             |
       | ServerRequestCacheWebFilter | (8) default
       |                             |
       +---------+-------------------+
                 |
                 |
                 |
       +---------v-------+
       |                 |
       | LogoutWebFilter | (9) configurable
       |                 |
       +---------+-------+
                 |
                 |
                 |
    +------------v------------------+
    |                               |
    | ExceptionTranslationWebFilter | (10) default
    |                               |
    +------------+------------------+
                 |
                 |
                 |
    +------------v------------+
    |                         |
    |  AuthorizationWebFilter | (11) default
    |                         |
    +-------------------------+
    
    - Figure 1. Unless otherwise specified, filters with 'default' word are added by Spring Security -

Looking at the diagram above (Figure 1), if we want to implement a JWT based security for our API (our use case in this repository), we 
have to focus on two filters: [AuthenticationWebFilter](https://github.com/spring-projects/spring-security/blob/master/web/src/main/java/org/springframework/security/web/server/authentication/AuthenticationWebFilter.java) and [AuthorizationWebFilter](https://github.com/spring-projects/spring-security/blob/master/web/src/main/java/org/springframework/security/web/server/authorization/AuthorizationWebFilter.java), but let's start with the default configuration that Spring Security Webflux give to us. 
Also, you could find the order of the filters here: [SecurityWebFiltersOrder](https://github.com/spring-projects/spring-security/blob/master/config/src/main/java/org/springframework/security/config/web/server/SecurityWebFiltersOrder.java).

### 3.1 Default Config 

Spring Security Webflux configures the filter chain (see Figure 1) automatically for us in [WebFluxSecurityConfiguration](https://github.com/spring-projects/spring-security/blob/master/config/src/main/java/org/springframework/security/config/annotation/web/reactive/WebFluxSecurityConfiguration.java#L98), through [ServerHttpSecurity](https://github.com/spring-projects/spring-security/blob/master/config/src/main/java/org/springframework/security/config/web/server/ServerHttpSecurity.java) bean, 
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
This method (`springSecurityFilterChain`) is only executed if Spring Security does not find a 
SecurityWebFilterChain in the application context otherwise, it will load the SecurityWebFilterChain provided by us. 
Apparently, it's look simple but this method do a lot of things behind the scenes, in fact configure a whole 
chain. For example, if our application has the following config:

```kotlin
@Configuration
@EnableWebFluxSecurity
class MyWebfluxSecurityConfig
```

...and we don't have OAuth2 added as a dependency, Spring Security is going to add an http basic and form login authentication (with the famous login page)
filters for all incoming requests, besides all others filters appearing in Figure 1 (headers, csrf, logout, etc).

But wait..., where does that `ServerHttpSecurity` bean comes from? This bean is injected by Spring Security through [ServerHttpSecurityConfiguration](https://github.com/spring-projects/spring-security/blob/master/config/src/main/java/org/springframework/security/config/annotation/web/reactive/ServerHttpSecurityConfiguration.java#L122) config class, that 
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

...so apart from the http basic and form login (and the others), here we can see that Spring Security also, adds the HTTP response headers [HeaderSpec](https://github.com/spring-projects/spring-security/blob/master/config/src/main/java/org/springframework/security/config/web/server/ServerHttpSecurity.java#L3269), 
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
    fun userDetailsService(): MapReactiveUserDetailsService {
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

So far so good, we saw what is doing Spring Security for us, also we know which order has the filter chain in Spring Security Webflux projects 
and what is the default configuration. At this point, we could say that **with ServerHttpSecurity 
bean we can disable, enable or setting ours filters instead of the default ones**. In this section, I will explain how we can explicitly configure our chain.

Previously, I mention that simply adding a method to our configuration that adds the ServerHttpSecurity bean to our application 
context we can start configure whatever we want. Imagine for example, we want to remove the default authentication filters, we can do it with the following code:

```kotlin
@Configuration
@EnableWebFluxSecurity
class MyWebfluxSecurityConfig {
    /*
        ServerHttpSecurity bean is injected by Spring Security, 
        see section 3.1 for knowing where comes from.
    */
    @Bean
    fun springWebFilterChain(http: ServerHttpSecurity) = http.build()
}
```

Doing that, we add our custom SecurityWebFilterChain to the application context, then Spring Security doesn't load the default config. 
We are getting the SecurityWebFilterChain injected by Spring security that only has the authentication manager, logout page and 
security header filters without any authentication or authorization filters.

:warning: **Please don't do this on production is only for educational purpose**

If a client makes an HTTP request to our API is gonna be able to do it without problems, we 
have no security at all. See 3.1 section if you want to remember the default config.

Now you know how to explicit configure the chain, let's add some security to our API!

### 3.3 Authentication

Spring Security supports authentication for incoming requests, and represents it with [Authentication](https://github.com/spring-projects/spring-security/blob/master/core/src/main/java/org/springframework/security/core/Authentication.java) type. 
This type is used to represent the entity (user or service) we want to authenticate (verify that the entity is who it claims to be).

Spring Security Webflux use the [AuthenticationWebFilter](https://github.com/spring-projects/spring-security/blob/master/web/src/main/java/org/springframework/security/web/server/authentication/AuthenticationWebFilter.java) for this purpose and 
it could be configured to do whatever authentication logic we want.

Looking closer to that filter we can see his dependency graph:

![AuthenticationWebFilter Dependency Graph](/diagrams/authentication_web_filter.png?raw=true "AuthenticationWebFilter Dependency Graph")

Most of them are provided by default but at least one ([ReactiveAuthenticationManagerResolver](https://github.com/spring-projects/spring-security/blob/master/core/src/main/java/org/springframework/security/authentication/ReactiveAuthenticationManagerResolver.java)) must be 
provided by the user. This interface resolves a [ReactiveAuthenticationManager](https://github.com/spring-projects/spring-security/blob/master/core/src/main/java/org/springframework/security/authentication/ReactiveAuthenticationManager.java) from a given context (ServerWebExchange in this case). 
This manager determines if the given Authentication is valid or not, for us an Authentication object contains the 
username and password of the user that we want to authenticate. 

But how we can do that? who is the responsible to convert the ServerWebExchange (incoming request) to an Authentication object? 

To know that we must know before which path a ServerWebExchange follows when arrives to the AuthenticationWebFilter. This could 
be seen in the source code of the `filter()` method of AuthenticationWebFilter:

```java
@Override
public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
    return this.requiresAuthenticationMatcher.matches(exchange) // (1)
        .filter(matchResult -> matchResult.isMatch())
        .flatMap(matchResult -> this.authenticationConverter.convert(exchange)) // (2)
        .switchIfEmpty(chain.filter(exchange).then(Mono.empty()))
        .flatMap(token -> authenticate(exchange, chain, token)) // (3)
        .onErrorResume(AuthenticationException.class, e -> this.authenticationFailureHandler
            .onAuthenticationFailure(new WebFilterExchange(exchange, chain), e));
}

private Mono<Void> authenticate(ServerWebExchange exchange, WebFilterChain chain, Authentication token) {
    return this.authenticationManagerResolver.resolve(exchange)
        .flatMap(authenticationManager -> authenticationManager.authenticate(token))
        .switchIfEmpty(Mono.defer(() -> Mono.error(new IllegalStateException("No provider found for " + token.getClass()))))
        .flatMap(authentication -> onAuthenticationSuccess(authentication, new WebFilterExchange(exchange, chain)))
        .doOnError(AuthenticationException.class, e -> {
            if (logger.isDebugEnabled()) {
                logger.debug("Authentication failed: " + e.getMessage());
            }
        });
}

protected Mono<Void> onAuthenticationSuccess(Authentication authentication, WebFilterExchange webFilterExchange) {
    ServerWebExchange exchange = webFilterExchange.getExchange();
    SecurityContextImpl securityContext = new SecurityContextImpl();
    securityContext.setAuthentication(authentication);
    return this.securityContextRepository.save(exchange, securityContext)
        .then(this.authenticationSuccessHandler
            .onAuthenticationSuccess(webFilterExchange, authentication))
        .subscriberContext(ReactiveSecurityContextHolder.withSecurityContext(Mono.just(securityContext)));
}
```

1. Checks if the request match a given pattern. This is done by [ServerWebExchangeMatcher](https://github.com/spring-projects/spring-security/blob/master/web/src/main/java/org/springframework/security/web/server/util/matcher/ServerWebExchangeMatcher.java). 
If success, continue with step 2, if not skip this filter and continue the chain. 
2. Converts the request to an unauthenticated Authentication object. This is done by [ServerAuthenticationConverter](https://github.com/spring-projects/spring-security/blob/master/web/src/main/java/org/springframework/security/web/server/authentication/ServerAuthenticationConverter.java). 
If the converter returns an empty Mono, continue the chain otherwise go step 3.
3. Verify the Authentication object provided by step 2. This step is done by [ReactiveAuthenticationManager](https://github.com/spring-projects/spring-security/blob/master/core/src/main/java/org/springframework/security/authentication/ReactiveAuthenticationManager.java). If the verification is not successful we can throw an exception, otherwise go step 4. 
4. On authentication success:
    1. Save the Authentication object in the security context (session). By [ServerSecurityContextRepository](https://github.com/spring-projects/spring-security/blob/master/web/src/main/java/org/springframework/security/web/server/context/ServerSecurityContextRepository.java).
    2. Execute [ServerAuthenticationSuccessHandler](https://github.com/spring-projects/spring-security/blob/master/web/src/main/java/org/springframework/security/web/server/authentication/ServerAuthenticationSuccessHandler.java).

This is the general algorithm that AuthenticationWebFilter follows, and in which we can customize all steps. In our case, the steps are:

1. We want to authenticate users through a POST to `/login` endpoint, our matcher looks at the request and see if this pattern match. We can use the factory method `pathMatchers()` that [ServerWebExchangeMatchers](/backend-server/src/main/kotlin/com/popokis/backend_server/application/WebConfig.kt#L71) provides 
to create our custom matcher. 
2. Our converter gets from the body a JSON with `username` and `password` attributes and creates an unauthenticated Authentication object with them. Done by [JWTConverter](/backend-server/src/main/kotlin/com/popokis/backend_server/application/security/authentication/JWTConverter.kt). 
3. [AbstractUserDetailsReactiveAuthenticationManager](https://github.com/spring-projects/spring-security/blob/master/core/src/main/java/org/springframework/security/authentication/AbstractUserDetailsReactiveAuthenticationManager.java#L98) gets the principal (username) and the credentials (password) from the Authentication object created in step 2 and: 
    1. [AbstractUserDetailsReactiveAuthenticationManager](https://github.com/spring-projects/spring-security/blob/master/core/src/main/java/org/springframework/security/authentication/AbstractUserDetailsReactiveAuthenticationManager.java#L100) looks into the database if the user exist with [CustomerReactiveUserDetailsService](/backend-server/src/main/kotlin/com/popokis/backend_server/application/security/authentication/CustomerReactiveUserDetailsService.kt), if exists go to step 3.ii, otherwise throw Unauthorized error. 
    2. [AbstractUserDetailsReactiveAuthenticationManager](https://github.com/spring-projects/spring-security/blob/master/core/src/main/java/org/springframework/security/authentication/AbstractUserDetailsReactiveAuthenticationManager.java#L103) checks if passwords match, if so authentication success, if not throw Unauthorized error.
4. On authentication success:
    1. Our project is just an HTTP API and by default should be stateless, then we don't want to create a session so skip it. Done by [NoOpServerSecurityContextRepository](https://github.com/spring-projects/spring-security/blob/master/web/src/main/java/org/springframework/security/web/server/context/NoOpServerSecurityContextRepository.java).
    2. Execute our [JWTServerAuthenticationSuccessHandler](/backend-server/src/main/kotlin/com/popokis/backend_server/application/security/authentication/JWTServerAuthenticationSuccessHandler.kt) that generates an access and a refresh token and put them in the header of the response.

We are following these steps customizing [AuthenticationWebFilter](/backend-server/src/main/kotlin/com/popokis/backend_server/application/WebConfig.kt#L70), and our ServerHttpSecurity configuration looks like:

```kotlin
@Bean
fun configureSecurity(http: ServerHttpSecurity, jwtAuthenticationFilter: AuthenticationWebFilter): SecurityWebFilterChain {
    return http
            .csrf().disable()
            .logout().disable()
            .addFilterAt(jwtAuthenticationFilter, SecurityWebFiltersOrder.AUTHENTICATION)
            .build()
}
```
 
At this point we have been customized our authentication flow, how should we authorize users to use our APIs?

### 3.4 Authorization

Spring Security could be used to give permission to our clients for use certain endpoints of our API, these permissions could be role based, scope based or both and are called [GrantedAuthority](https://github.com/spring-projects/spring-security/blob/master/core/src/main/java/org/springframework/security/core/GrantedAuthority.java). 
We give permissions in the authentication process depending of the user we give one or the other. **(I will skip this part but is a WIP)**

For now, we want to authorize users checking the validity of the JWT that comes in every request (for example, if we need to do a role based authorization this role should come in the JWT). The validity for us is:

1. If the token is expired. 
2. If token was given by us (is signed with our signature). 

We have to types of endpoints in our application: the public ones and the private ones. The public ones are the endpoints of the static files and `/login` endpoint, 
and the private ones are the rest.

## Build project

1. Build frontend

`mvn -U clean install -pl :frontend-client`

2. Build backend

`mvn -U clean test package -pl :backend-server`

## MongoDB Index creation

Index creation must be *explicitly* enabled, since Spring Data MongoDB version 3.0, to prevent undesired effects with collection lifecyle and performance impact. In our project when we add a new `@Document` class, if this document class has any index, this index should be created manual. See [002_create_customer_collection.js](/data/mongo/002_create_customer_collection.js) for more info.

## Spring Security Webflux Authentication Flow

`LoginServerWebExchangeMatcher` > `JWTConverter` > `UserDetailsRepositoryReactiveAuthenticationManager` > `JWTServerAuthenticationSuccessHandler`