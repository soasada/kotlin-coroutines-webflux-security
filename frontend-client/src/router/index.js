import Vue from 'vue';
import VueRouter from 'vue-router';

Vue.use(VueRouter);

function loadView(view) {
    return () => import(/* webpackChunkName: "view-[request]" */ `@/views/${view}.vue`);
}

const routes = [
    {
        path: '/',
        name: 'Home',
        component: loadView('Home')
    },
    {
        path: '/about',
        name: 'About',
        component: loadView('About')
    },
    {
        path: '/customers',
        name: 'Customers',
        component: loadView('Customers'),
        meta: {requiresAuth: true}
    },
    {
        path: '/login',
        name: 'Login',
        component: loadView('Login')
    }
]

const router = new VueRouter({
    routes
})

export default router
