from django.urls import path, include
from auth_app.views import *
from . import views
from .views import csrf_token

urlpatterns = [
    path('api/users/', UserListCreateView.as_view(), name='user-list-create'),
    path('api/users/<int:id>/', UserDetailView.as_view(), name='user-detail'), 
    path('token/', ObtainTokenPairWithRoleView.as_view(), name='token_obtain_pair'),
    path('admin-only/', AdminOnlyView.as_view(), name='admin-only'),
    path('staff-only/', StaffOnlyView.as_view(), name='staff-only'),
    path('api/login/', views.UserLogin.as_view(), name='user-login'),
    path('api/logout/', views.UserLogout.as_view(), name='user-logout'),
    path('api/reset-password/', PasswordResetRequestView.as_view(), name='password_reset'),
    path('reset/<uidb64>/<token>/', password_reset_confirm, name='password_reset_confirm'),
    path('api/personnel/', PersonnelListCreateView.as_view(), name='event-list-create'),
    path('api/personnel/<int:id>/', PersonnelDetailView.as_view(), name='event_detail'),
    path('api/contacts/', ContactsListCreateView.as_view(), name='contacts-list-create'),
    path('api/contacts/<int:id>/', ContactDetailView.as_view(), name='contacts-detail'),  
    path('api/csrf-token/', csrf_token, name='csrf-token'),
    # path('save-transaction/', SaveTransactionView.as_view(), name='save-transaction'),
    # path('api/send-receipt-email/', send_receipt_email, name='send_receipt_email'),
]

