const BASE_URL = '/api';

export const customInstance = async <T>(config: {
  url: string;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
  params?: Record<string, string>;
  data?: unknown;
  headers?: Record<string, string>;
}): Promise<T> => {
  const { url, method, params, data, headers } = config;

  const queryString = params
    ? '?' + new URLSearchParams(params).toString()
    : '';

  const response = await fetch(`${BASE_URL}${url}${queryString}`, {
    method,
    headers: {
      'Content-Type': 'application/json',
      ...headers,
    },
    body: data ? JSON.stringify(data) : undefined,
  });

  if (!response.ok) {
    throw new Error(`HTTP error! status: ${response.status}`);
  }

  return response.json();
};

export default customInstance;
