import { Navigate, useLocation } from 'react-router-dom';
import { isAuthenticated } from '@/utils/sessionUtils';

interface ProtectedRouteProps {
  children: React.ReactNode;
}

const ProtectedRoute = ({ children }: ProtectedRouteProps) => {
  const location = useLocation();

  if (!isAuthenticated()) {
    // Redirect to sign in page with the return url
    return <Navigate to="/signin" state={{ from: location }} replace />;
  }

  return <>{children}</>;
};

export default ProtectedRoute; 