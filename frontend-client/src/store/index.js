import Vue from 'vue';
import Vuex from 'vuex';
import jwt from 'jsonwebtoken';
import http from '@/http';

Vue.use(Vuex);

export default new Vuex.Store({
    state: {
        token: null,
        signInError: false,
        signInErrorMsg: ''
    },
    mutations: {
        SET_TOKEN(state, token) {
            state.token = token;
        },
        SET_SIGN_IN_ERROR(state, signInError) {
            state.signInError = signInError;
        },
        SET_SIGN_IN_ERROR_MSG(state, signInErrorMsg) {
            state.signInErrorMsg = signInErrorMsg;
        }
    },
    actions: {
        signIn({commit}, {username, password, router, route}) {
            http.post('/login', {username: username, password: password})
                .then(response => {
                    console.log('REFRESH: ' + response.headers.get('jwt-refresh-token'));
                    const token = response.headers.get('authorization');
                    commit('SET_TOKEN', token);
                    commit('SET_SIGN_IN_ERROR', false);
                    commit('SET_SIGN_IN_ERROR_MSG', '');
                    sessionStorage.setItem('token', token);
                    if (route.query.redirect) {
                        router.push(route.query.redirect);
                    } else {
                        router.push('home');
                    }
                })
                .catch(error => {
                    commit('SET_TOKEN', null);
                    commit('SET_SIGN_IN_ERROR', true);
                    commit('SET_SIGN_IN_ERROR_MSG', error);
                    sessionStorage.removeItem('token');
                });
        },
        signOut({commit}) {
            commit('SET_TOKEN', null);
            sessionStorage.removeItem('token');
        }
    },
    modules: {},
    getters: {
        isAuthenticated(state) {
            if (state.token === null || state.token === undefined) {
                return false;
            }

            const decoded = jwt.decode(state.token.replace('Bearer ', ''));
            const expDate = new Date(decoded.exp * 1000);
            const now = new Date();
            return expDate > now;
        }
    }
});
