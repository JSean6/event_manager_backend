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
    path('api/events/', EventsListCreateView.as_view(), name='event-list-create'),
    path('api/events/<int:id>/', EventDetailView.as_view(), name='event_detail'),
    path('api/tickets/', TicketsListCreateView.as_view(), name='ticket-list-create'),
    path('api/tickets/<int:id>/', TicketDetailView.as_view(), name='ticket-detail'),  
    path('api/vendors/', VendorsListCreateView.as_view(), name='vendors-list-create'),
    path('api/vendors/<int:id>/', VendorDetailView.as_view(), name='vendors-detail'),
    path('api/contacts/', ContactsListCreateView.as_view(), name='contacts-list-create'),
    path('api/contacts/<int:id>/', ContactDetailView.as_view(), name='contacts-detail'),  
    path('api/csrf-token/', csrf_token, name='csrf-token'),
]
