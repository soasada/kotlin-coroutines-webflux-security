<template>
    <div class="customer-list">
        <ol>
            <li v-for="customer in customers" :key="customer.id" >
                {{ customer.email }}
            </li>
        </ol>
    </div>
</template>

<script>
    import http from '@/http';

    export default {
        name: 'CustomerList',
        data() {
            return {
                customers: []
            };
        },
        mounted() {
            this.loadCustomers();
        },
        methods: {
            loadCustomers() {
                const self = this;
                http.get('/v1/customers')
                    .then(response => {
                        response.json().then(customersJson => {
                            for (let i = 0; i < customersJson.length; i++) {
                                self.customers.push(customersJson[i]);
                            }
                        });
                    })
                    .catch(error => console.error(error));
            }
        }
    }
</script>

<style scoped>

</style>