from rest_framework import generics
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import permissions, status
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import status
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth import get_user_model

from .models import *
from .serializers import *
from django.contrib.auth.tokens import default_token_generator

from rest_framework import generics
from .models import CustomUser
from .serializers import CustomUserSerializer
from .permissions import IsAdminUser, IsStaffUser
from django.contrib import messages
from django.shortcuts import render, redirect
from django.contrib.auth.forms import SetPasswordForm


from django.contrib.auth import get_user_model, login, logout
from rest_framework.authentication import SessionAuthentication
from rest_framework.views import APIView
from rest_framework.response import Response
from .serializers import UserRegisterSerializer, UserLoginSerializer
from rest_framework import permissions, status
from .validations import *
from django.http import JsonResponse
from django.middleware.csrf import get_token

def csrf_token(request):
    return JsonResponse({'csrfToken': get_token(request)})

User = get_user_model()
class UserRegister(APIView):
    permission_classes = (permissions.AllowAny,)
    
    def post(self, request):
        clean_data = custom_validation(request.data)
        serializer = UserRegisterSerializer(data=clean_data)
        if serializer.is_valid(raise_exception=True):
            user = serializer.create(clean_data)
            if user:
                return Response({
                    "user": UserRegisterSerializer(user).data,
                    "message": "User registered successfully."
                }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserLogin(generics.ListCreateAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = UserLoginSerializer
    permission_classes = [AllowAny]
    
    def post(self, request):
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data
            # You can return a token or any other response here
            return Response({"detail": "Successfully logged in"}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def get(self, request):
        serializer = UserLoginSerializer(request.user)
        return Response({'user': serializer.data}, status=status.HTTP_200_OK)

class UserLogout(APIView):
    def post(self, request, *args, **kwargs):
        logout(request)
        return Response({"detail": "Successfully logged out"}, status=status.HTTP_200_OK)


class UserView(APIView):
    permission_classes = (permissions.IsAuthenticated,)
    authentication_classes = (SessionAuthentication)
    ##
    def get(self, request):
        serializer = UserSerializer(request.user)
        return Response({'user': serializer.data}, status=status.HTTP_200_OK)

class AdminOnlyView(generics.ListCreateAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = CustomUserSerializer
    permission_classes = [IsAdminUser]

class StaffOnlyView(generics.ListCreateAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = CustomUserSerializer
    permission_classes = [IsStaffUser]


class UserListCreateView(generics.ListCreateAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = CustomUserSerializer
    permission_classes = [IsAuthenticated]

    def get_permissions(self):
        if self.request.method == 'POST':
            self.permission_classes = [AllowAny]
        return super().get_permissions()

class ObtainTokenPairWithRoleView(APIView):
    permission_classes = (AllowAny,)

    def post(self, request, *args, **kwargs):
        serializer = UserLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data["user"]
        refresh = RefreshToken.for_user(user)
        return Response({
            "refresh": str(refresh),
            "access": str(refresh.access_token),
            "role": user.role
        })

class PasswordResetRequestView(APIView):
    serializer_class = PasswordResetSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response({'success': 'Password reset email has been sent.'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

def password_reset_confirm(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        if request.method == 'POST':
            form = SetPasswordForm(user, request.POST)
            if form.is_valid():
                form.save()
                messages.success(request, 'Your password has been reset successfully. You can now log in with your new password.')
                return redirect('login') 
        else:
            form = SetPasswordForm(user)

        return render(request, 'password_reset_confirm.html', {'form': form})
    else:
        messages.error(request, 'The password reset link is invalid or has expired.')
        return redirect('password_reset')  


class EventsListCreateView(generics.ListCreateAPIView):
    queryset = Events.objects.all()
    serializer_class = EventsSerializer
    permission_classes = [AllowAny]

class TicketsListCreateView(generics.ListCreateAPIView):
    queryset = Tickets.objects.all()
    serializer_class = TicketsSerializer
    permission_classes = [AllowAny]

class VendorsListCreateView(generics.ListCreateAPIView):
    queryset = Vendors.objects.all()
    serializer_class = VendorsSerializer
    permission_classes = [AllowAny]
    
class ContactsListCreateView(generics.ListCreateAPIView):
    queryset = Contacts.objects.all()
    serializer_class = ContactsSerializer
    permission_classes = [AllowAny]