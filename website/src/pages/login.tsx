import { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Github, Loader2 } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';

const LoginPage = () => {
  const [searchParams] = useSearchParams();
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  const handleLogin = async () => {
    setIsLoading(true);
    setError(null);

    // The 'origin_host' query parameter tells the backend where to redirect after success.
    const originHost = searchParams.get('origin_host');

    if (!originHost) {
      setError('Missing required "origin_host" parameter. Cannot proceed with authentication.');
      setIsLoading(false);
      return;
    }

    try {
      // The backend will generate the correct GitHub URL with the state parameter.
      const response = await fetch(`/api/v1/auth/github?origin_host=${encodeURIComponent(originHost)}`);
      if (!response.ok) {
        throw new Error('Failed to get authentication URL from the server.');
      }
      const data = await response.json();
      
      // Redirect the user to GitHub to authorize the application.
      window.location.href = data.data.auth_url;

    } catch (err) {
      setError(err instanceof Error ? err.message : 'An unknown error occurred.');
      setIsLoading(false);
    }
  };

  useEffect(() => {
    // Automatically trigger the login flow if the origin_host is present.
    const originHost = searchParams.get('origin_host');
    if (originHost) {
      handleLogin();
    }
  }, [searchParams]);

  return (
    <div className="flex items-center justify-center min-h-screen bg-background">
      <Card className="w-full max-w-md">
        <CardHeader className="text-center">
          <CardTitle className="text-2xl">ArchGuardian Authentication</CardTitle>
          <CardDescription>
            {isLoading ? 'Redirecting you to GitHub for authentication...' : 'Click the button to log in.'}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="flex justify-center items-center p-8">
              <Loader2 className="h-12 w-12 animate-spin text-primary" />
            </div>
          ) : (
            <Button onClick={handleLogin} className="w-full" disabled={isLoading}>
              <Github className="mr-2 h-4 w-4" /> Continue with GitHub
            </Button>
          )}
          {error && (
            <p className="text-sm text-destructive mt-4 text-center">{error}</p>
          )}
        </CardContent>
      </Card>
    </div>
  );
};

export default LoginPage;