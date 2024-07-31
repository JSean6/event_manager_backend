from rest_framework import generics
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.forms import SetPasswordForm
from django.contrib import messages
from django.shortcuts import render, redirect
from django.contrib.auth import logout
from django.middleware.csrf import get_token
from django.http import JsonResponse
from rest_framework import status


from .models import CustomUser, Events, Tickets, Vendors, Contacts
from .serializers import (
    CustomUserSerializer, UserRegisterSerializer, UserLoginSerializer, 
    EventsSerializer, TicketsSerializer, VendorsSerializer, ContactsSerializer, PasswordResetSerializer
)
from .permissions import IsAdminUser, IsStaffUser
from .validations import custom_validation

from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.views import APIView
from .models import TicketTransaction
from .serializers import TicketTransactionSerializer
from django.core.mail import send_mail
from django.conf import settings

User = get_user_model()

def csrf_token(request):
    return JsonResponse({'csrfToken': get_token(request)})

class UserRegister(APIView):
    permission_classes = (AllowAny,)
    
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

class UserDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = CustomUserSerializer
    lookup_field = 'id'
    permission_classes = [IsAuthenticated]

class UserLogin(generics.ListCreateAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = UserLoginSerializer
    permission_classes = [AllowAny]
    
    def post(self, request):
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data
            refresh = RefreshToken.for_user(user)
            return Response({
                "refresh": str(refresh),
                "access": str(refresh.access_token),
                "role": user.role
            }, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def get(self, request):
        serializer = UserLoginSerializer(request.user)
        return Response({'user': serializer.data}, status=status.HTTP_200_OK)

class UserLogout(APIView):
    def post(self, request, *args, **kwargs):
        logout(request)
        return Response({"detail": "Successfully logged out"}, status=status.HTTP_200_OK)

class UserView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        serializer = CustomUserSerializer(request.user)
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
    permission_classes = [AllowAny]

    def get_permissions(self):
        if self.request.method == 'POST':
            self.permission_classes = [AllowAny]
        return super().get_permissions()

class ObtainTokenPairWithRoleView(APIView):
    permission_classes = [AllowAny]

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

class EventDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Events.objects.all()
    serializer_class = EventsSerializer
    lookup_field = 'id'
    permission_classes = [IsAuthenticated]

class TicketsListCreateView(generics.ListCreateAPIView):
    queryset = Tickets.objects.all()
    serializer_class = TicketsSerializer
    permission_classes = [AllowAny]

class TicketDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Tickets.objects.all()
    serializer_class = TicketsSerializer
    lookup_field = 'id'
    permission_classes = [IsAuthenticated]

class VendorsListCreateView(generics.ListCreateAPIView):
    queryset = Vendors.objects.all()
    serializer_class = VendorsSerializer
    permission_classes = [AllowAny]

class VendorDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Vendors.objects.all()
    serializer_class = VendorsSerializer
    lookup_field = 'id'
    permission_classes = [IsAuthenticated]

class ContactsListCreateView(generics.ListCreateAPIView):
    queryset = Contacts.objects.all()
    serializer_class = ContactsSerializer
    permission_classes = [AllowAny]

class ContactDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = Contacts.objects.all()
    serializer_class = ContactsSerializer
    lookup_field = 'id'
    permission_classes = [IsAuthenticated]

class SaveTransactionView(generics.ListCreateAPIView):
    queryset = TicketTransaction.objects.all()
    serializer_class = TicketTransactionSerializer

# views.py

from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
import json
from .utils import send_ticket_email

@csrf_exempt
def send_receipt_email(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        email = data.get('email')
        receipt = data.get('receipt')
        
        if not email or not receipt:
            return JsonResponse({'error': 'Email and receipt data are required'}, status=400)
        
        subject = "Your Ticket Purchase Receipt"
        content = f"""
        <h1>Thank you for your purchase!</h1>
        <p>Here are your ticket details:</p>
        <p>Event Title: {receipt['title']}</p>
        <p>Category: {receipt['category']}</p>
        <p>Venue: {receipt['venue']}</p>
        <p>Duration: {receipt['duration']}</p>
        <p>Name: {receipt['name']}</p>
        <p>Email: {receipt['email']}</p>
        <p>Number of Tickets: {receipt['number_of_tickets']}</p>
        <p>Total Price: Ksh.{receipt['totalPrice']}</p>
        <p>Date: {receipt['date']}</p>
        """
        
        response = send_ticket_email(email, subject, content)
        if response.status_code == 200:
            return JsonResponse({'status': 'Email sent'})
        else:
            return JsonResponse({'error': 'Failed to send email'}, status=500)
    
    return JsonResponse({'error': 'Invalid request method'}, status=405)
