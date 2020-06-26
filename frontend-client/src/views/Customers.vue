<template>
    <div class="customers">
        <CustomerList></CustomerList>
    </div>
</template>

<script>
    import CustomerList from '@/components/CustomerList';

    export default {
        name: 'Customers',
        components: {
            CustomerList
        }
    }
</script>