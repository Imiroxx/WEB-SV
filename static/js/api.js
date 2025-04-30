class ApiClient {
    constructor() {
        this.baseUrl = '/api';
    }

    async get(endpoint, params = {}) {
        const url = new URL(`${this.baseUrl}${endpoint}`, window.location.origin);
        Object.keys(params).forEach(key => url.searchParams.append(key, params[key]));

        const response = await fetch(url, {
            method: 'GET',
            headers: this._getHeaders()
        });

        return this._handleResponse(response);
    }

    async post(endpoint, data = {}) {
        const response = await fetch(`${this.baseUrl}${endpoint}`, {
            method: 'POST',
            headers: this._getHeaders(),
            body: JSON.stringify(data)
        });

        return this._handleResponse(response);
    }

    async postFormData(endpoint, formData) {
        const response = await fetch(`${this.baseUrl}${endpoint}`, {
            method: 'POST',
            headers: {
                'Authorization': this._getAuthHeader()
            },
            body: formData
        });

        return this._handleResponse(response);
    }

    async put(endpoint, data = {}) {
        const response = await fetch(`${this.baseUrl}${endpoint}`, {
            method: 'PUT',
            headers: this._getHeaders(),
            body: JSON.stringify(data)
        });

        return this._handleResponse(response);
    }

    async delete(endpoint, data = {}) {
        const response = await fetch(`${this.baseUrl}${endpoint}`, {
            method: 'DELETE',
            headers: this._getHeaders(),
            body: JSON.stringify(data)
        });

        return this._handleResponse(response);
    }

    _getHeaders() {
        return {
            'Content-Type': 'application/json',
            'Authorization': this._getAuthHeader()
        };
    }

    _getAuthHeader() {
        // Здесь можно добавить логику для получения токена авторизации
        return '';
    }

    async _handleResponse(response) {
        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || 'Произошла ошибка');
        }

        return data;
    }
}

const api = new ApiClient();
