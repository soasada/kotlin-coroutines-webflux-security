<template>
    <div class="login">
        <form @submit.prevent="signIn">
            <div class="form-row">
                <div class="col">
                    <label for="usernameInput">Username</label>
                    <input id="usernameInput" type="text" class="form-control" placeholder="Username"
                           v-model="model.username">
                </div>
                <div class="col">
                    <label for="passwordInput">Password</label>
                    <input id="passwordInput" type="password" class="form-control" placeholder="Password"
                           v-model="model.password">
                </div>
            </div>
            <button type="submit" class="btn btn-success">Sign In</button>
        </form>
    </div>
</template>

<script>
    export default {
        name: 'Login',
        data() {
            return {
                model: {}
            };
        },
        computed: {
            signInError() {
                return this.$store.state.signInError;
            },
            signInErrorMsg() {
                return this.$store.state.signInErrorMsg;
            }
        },
        methods: {
            signIn() {
                const self = this;
                this.$store.dispatch('signIn', {
                    username: this.model.username,
                    password: this.model.password,
                    router: self.$router,
                    route: self.$route
                });
            }
        }
    }
</script>