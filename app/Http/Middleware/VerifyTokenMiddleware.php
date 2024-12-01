<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use Symfony\Component\HttpFoundation\Response;

class VerifyTokenMiddleware
{
    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next)
{
    $token = $request->input('token');

    if (!$token) {
        return response()->json(['error' => 'Unauthorized'], 401);
    }

    try {
        $response = Http::timeout(10)->post("http://laravel-auth:8002/api/auth/check-token", [
            "token" => $token
        ]);

        if ($response->failed()) {
            return response()->json([
                'error' => 'Invalid token',
                'details' => $response->body()
            ], 401);
        }

        return $next($request);
    } catch (\Exception $e) {
        \Log::error('Token verification error', [
            'message' => $e->getMessage(),
            'trace' => $e->getTraceAsString()
        ]);

        return response()->json([
            'error' => 'Token verification failed',
            'exception' => $e->getMessage()
        ], 500);
    }
}
}
