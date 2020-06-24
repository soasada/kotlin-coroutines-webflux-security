# Spring WebFlux + Spring Security + Kotlin Coroutines

Hi! If you are one of those people like me that, are trying to learn Spring Webflux with Kotlin and Spring Security 
this repository is for you. As you probably already know, the documentation about using Spring Security with Spring WebFlux 
if very scarce and if we add Kotlin on top of that, is even more. This lack of documentation has encouraged me to do this repository, 
I will try to explain how to make a custom security configuration with Kotlin coroutines with a "close-to-real-world" minimal example.

There are few resources over the internet explaining this topic, but most of them have incomplete or incorrect information, 
I think that this is for two reasons: a poor documentation and young technology. So even trying to do it perfectly, I'm pretty sure 
I made lot of mistakes, if you find them (in the code or in the README), please make a pull request. Together we could make a better documentation for everyone.

I'm assuming that you have some knowledge with Spring WebFlux (know what Mono and Flux is), so I will skip the explanation of WebFlux, 
but I'm going to shed new light on how we can work with Mono and Flux with Kotlin coroutines in a "imperative" way.

## Build project

1. Build frontend

`mvn -U clean install -pl :frontend-client`

2. Build backend

`mvn -U clean test package -pl :backend-server`

## Mongo Index creation

Index creation must be *explicitly* enabled, since Spring Data MongoDB version 3.0, to prevent undesired effects with collection lifecyle and performance impact. In our project when we add a new `@Document` class, if this document class has any index, this index should be created manual. See [002_create_admin_collection.js](/data/mongo/002_create_admin_collection.js) for more info.

## Spring Security Webflux Authentication Flow

`LoginServerWebExchangeMatcher` > `JWTConverter` > `UserDetailsRepositoryReactiveAuthenticationManager` > `JWTServerAuthenticationSuccessHandler`