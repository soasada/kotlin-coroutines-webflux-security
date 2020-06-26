export default {
    get(resource) {
        return this.execute('GET', resource);
    },

    post(resource, data) {
        return this.execute('POST', resource, data);
    },

    execute(method, resource, data = {}) {
        if (Object.keys(data).length === 0 && data.constructor === Object) {
            return fetch(resource, {
                method: method,
                mode: 'same-origin',
                cache: 'no-cache',
                credentials: 'same-origin',
                headers: {
                    'Content-Type': 'application/json'
                },
                redirect: 'follow',
                referrerPolicy: 'no-referrer'
            });
        } else {
            return fetch(resource, {
                method: method,
                mode: 'same-origin',
                cache: 'no-cache',
                credentials: 'same-origin',
                headers: {
                    'Content-Type': 'application/json'
                },
                redirect: 'follow',
                referrerPolicy: 'no-referrer',
                body: JSON.stringify(data)
            });
        }
    }
}