from django.core.mail import send_mail
from django.conf import settings
from django.core.cache import cache
from django.shortcuts import render
from django.views import View
from rest_framework import viewsets, status
from rest_framework.response import Response
from django.shortcuts import get_object_or_404
from rest_framework.decorators import api_view
from django.contrib.auth import login as auth_login
from .models import Notificationthings
from .models import Password
from .serializers import NotificationSerializer
from .serializers import PasswordSerializer
from django.http import JsonResponse
from django.db import connection
from rest_framework.views import APIView
from rest_framework import viewsets, status
from rest_framework.views import APIView
import bcrypt
from django.core.mail import send_mail
import logging
from django.conf import settings
from django.core.cache import cache
from django.utils.crypto import get_random_string



class NotificationViewSet(viewsets.ModelViewSet):
    queryset = Notificationthings.objects.all()
    serializer_class = NotificationSerializer

    def create(self, request, *args, **kwargs):
        user_id = request.data.get('userId')
        print(user_id)
        product_announcement = request.data.get('product_announcement', False)
        insights_tips = request.data.get('insights_tips', False)
        special_offers = request.data.get('special_offers', False)
        price_alerts = request.data.get('price_alerts', False)
        account_activity = request.data.get('account_activity', False)
        messages = request.data.get('messages', False)

        # Check if the user_id exists in the database
        notification, created = Notificationthings.objects.get_or_create(
            user_id=user_id,
            defaults={
                'product_announcement': product_announcement,
                'insights_tips': insights_tips,
                'special_offers': special_offers,
                'price_alerts': price_alerts,
                'account_activity': account_activity,
                'messages': messages,
            }
        )

        if not created:
            notification.product_announcement = product_announcement
            notification.insights_tips = insights_tips
            notification.special_offers = special_offers
            notification.price_alerts = price_alerts
            notification.account_activity = account_activity
            notification.messages = messages
            notification.user_id = user_id
            notification.save()

        serializer = self.get_serializer(notification)
        if created:
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.data, status=status.HTTP_200_OK)

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)

        return Response(serializer.data)


class PasswordViewSet(viewsets.ModelViewSet):
    queryset = Password.objects.all()
    serializer_class = PasswordSerializer

    def create(self, request, *args, **kwargs):
        password_creation = request.data.get('password_creation')
        user_id = request.data.get('userId')

        if not password_creation:
            return Response({'error': 'Password creation field is required'}, status=status.HTTP_400_BAD_REQUEST)

        # Hash the password before saving
        hashed_password = bcrypt.hashpw(password_creation.encode('utf-8'), bcrypt.gensalt())

        password_setting, created = Password.objects.get_or_create(
            id=user_id,
            defaults={
                'password_creation': hashed_password.decode('utf-8'),
            }
        )


        if not created:
            password_setting.password_creation = hashed_password.decode('utf-8')
            password_setting.save()

        serializer = self.get_serializer(password_setting)
        return Response(serializer.data, status=status.HTTP_201_CREATED if created else status.HTTP_200_OK)

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        password_creation = request.data.get('password_creation')

        if password_creation:
            hashed_password = bcrypt.hashpw(password_creation.encode('utf-8'), bcrypt.gensalt())
            request.data['password_creation'] = hashed_password.decode('utf-8')

        serializer = self.get_serializer(instance, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)

        return Response(serializer.data)

# class RepasswordViewSet(viewsets.ModelViewSet):
#     queryset = Password.objects.all()
#     serializer_class = PasswordSerializer

#     def create(self, request, *args, **kwargs):
#         retype_password = request.data.get('retype_password')

#         if not retype_password:
#             return JsonResponse({'status': 'error', 'message': 'Retype password field is required'}, status=status.HTTP_400_BAD_REQUEST)

#         try:
#             password_setting = Password.objects.get(id=54321)
#             stored_password_hash = password_setting.password_creation.encode('utf-8')
#         except Password.DoesNotExist:
#             return JsonResponse({'status': 'error', 'message': 'Original password not found'}, status=status.HTTP_404_NOT_FOUND)

#         # Hash the retype_password for comparison
#         retype_password_hash = bcrypt.hashpw(retype_password.encode('utf-8'), bcrypt.gensalt())

#         if not bcrypt.checkpw(retype_password.encode('utf-8'), stored_password_hash):
#             return JsonResponse({'status': 'password_failure', 'message': 'Passwords do not match'}, status=status.HTTP_400_BAD_REQUEST)
        

#         return JsonResponse({'status': 'success', 'message': 'Passwords match'}, status=status.HTTP_200_OK)
    
class RepasswordViewSet(viewsets.ModelViewSet):
    queryset = Password.objects.all()
    serializer_class = PasswordSerializer
   

    def create(self, request, *args, **kwargs):
        user_id = request.data.get('userId')
        id = user_id
        password_creation = request.data.get('password_creation')
        retype_password = request.data.get('retype_password')

        print(type(password_creation), type(retype_password))

        # Hash the retype_password
        hashed_retype_password = bcrypt.hashpw(retype_password.encode('utf-8'), bcrypt.gensalt())

        password_setting, created = Password.objects.get_or_create(
            id=user_id,
            defaults={
                'retype_password': hashed_retype_password.decode('utf-8'),
            }
        )

        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM app_password")
            rows = cursor.fetchall()
        
        id_list = []
        password_list = []
        retype_list = []

        for i in rows:
            id_list.append(i[0])
            password_list.append(i[1])
            retype_list.append(i[2])
        index = 0
        if id in id_list:
            index = id_list.index(id)

        print(password_list[index] != retype_list[index], password_list[index], retype_list[index])

        
        if not retype_password:
            return JsonResponse({'status': 'error', 'message': 'Retype password field is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            password_setting = Password.objects.get(id=user_id)
            stored_password_hash = password_setting.password_creation.encode('utf-8')
        except Password.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'Original password not found'}, status=status.HTTP_404_NOT_FOUND)

        # Hash the retype_password for comparison
        retype_password_hash = bcrypt.hashpw(retype_password.encode('utf-8'), bcrypt.gensalt())

        print(bcrypt.checkpw(retype_password.encode('utf-8'), stored_password_hash))

        if not bcrypt.checkpw(retype_password.encode('utf-8'), stored_password_hash):
            return JsonResponse({'status': 'password_failure', 'message': 'Passwords do not match'})
        else:
            return JsonResponse({'status': 'password_match', 'message': 'Passwords match'})

        if not created:
            password_setting.retype_password = hashed_retype_password.decode('utf-8')
            password_setting.save()

        serializer = self.get_serializer(password_setting)
        if created:
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.data, status=status.HTTP_200_OK)
    
    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)

        return Response(serializer.data)   
class LogPassword(viewsets.ViewSet):
    
    # def list(self, request):
    #     user_id = request.data.get('userId')
    #     id = user_id
    #     with connection.cursor() as cursor:
    #         cursor.execute("SELECT * FROM app_password")
    #         rows = cursor.fetchall()
    #     print(rows)
        
    #     id_list = [row[0] for row in rows]
    #     logpassword_list = [row[1] for row in rows]
        
    #     print(id in id_list)
    #     if id in id_list:
    #         index = id_list.index(id)
    #         return JsonResponse({'status': 'User_Id_is_connected', 'message': 'Passwords do not match'})
    #     else:
    #         return JsonResponse({'status': 'Error', 'message': 'User not found'})
        
    def create(self, request):
        user_id = request.data.get('userId')
        id = user_id
        logmain_password = request.data.get('logmain_password')  # The user input password
        
        print("Input password (raw):", logmain_password)
        
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM app_password")
            rows = cursor.fetchall()  # Fetching all password records
            
        print("Fetched rows from DB:", rows)
        
        id_list = [row[0] for row in rows]  # List of IDs
        logpassword_list = [row[1] for row in rows]  # List of hashed passwords
        
        if id in id_list:
            index = id_list.index(id)  # Get the index of the user with the matching ID
            stored_password_hash = logpassword_list[index]  # Get the hashed password from the DB
            
            print(f"Stored hash from DB (for ID {id}):", stored_password_hash)
            
            # Check if the input password matches the hashed password from the DB
            if bcrypt.checkpw(logmain_password.encode('utf-8'), stored_password_hash.encode('utf-8')):
                print("Password match")
                return JsonResponse({'status': 'Password_Match', 'message': 'Password is correct'})
            else:
                print("Password does not match")
                return JsonResponse({'status': 'password_failure', 'message': 'Passwords do not match'})
        # elif len(id_list):
            
        else:
            print("User ID not found")
            return JsonResponse({'status': 'Error', 'message': 'User not found'})


class LogPasswordLock(viewsets.ViewSet):
    
    def create(self, request):
        user_id = request.data.get('userId')
        id = user_id
        logmain_password = request.data.get('logmain_password')  
        
        print("Input password (raw):", logmain_password)
        
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM app_password")
            rows = cursor.fetchall()  # Fetching all password records
            
        print("Fetched rows from DB:", rows)
        
        id_list = [row[0] for row in rows]  # List of IDs
        logpassword_list = [row[1] for row in rows]  # List of hashed passwords
        
        if id in id_list:
            index = id_list.index(id)  # Get the index of the user with the matching ID
            stored_password_hash = logpassword_list[index]  # Get the hashed password from the DB
            
            print(f"Stored hash from DB (for ID {id}):", stored_password_hash)
            
            # Check if the input password matches the hashed password from the DB
            if bcrypt.checkpw(logmain_password.encode('utf-8'), stored_password_hash.encode('utf-8')):
                print("Password match")
                return JsonResponse({'status': 'Password_Match', 'message': 'Password is correct'})
            else:
                print("Password does not match")
                return JsonResponse({'status': 'password_failure', 'message': 'Passwords do not match'})
        # elif len(id_list):
            
        else:
            print("User ID not found")
            return JsonResponse({'status': 'Error', 'message': 'User not found'})
        
    def list(self, request):
        user_id = request.query_params.get('userId')  
        id = user_id
        print(id)
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM app_password")
            rows = cursor.fetchall()
        print(rows)
        
        id_list = [row[0] for row in rows]
        logpassword_list = [row[1] for row in rows]
        
        print(id in id_list)
        if id in id_list:
            index = id_list.index(id)
            return JsonResponse({'status': 'User_Id_is_connected', 'message': 'Passwords do not match'})
        else:
            return JsonResponse({'status': 'Error', 'message': 'User not found'})
       
logger = logging.getLogger(__name__)
class GenerateOTP(APIView):
    def post(self, request):
        email = request.data.get('user_email')
        print(email)

        if not email:
            return Response({"message": "Email is required"}, status=status.HTTP_400_BAD_REQUEST)

        # Fetch user from CustomUser
        # try:
        #     user = CustomUser.objects.get(user_email=email)
        # except CustomUser.DoesNotExist:
        #     return Response({"message": "User not found"}, status=status.HTTP_404_NOT_FOUND)

        # Generate OTP
        otp = get_random_string(length=6, allowed_chars='0123456789')

        # Store OTP in cache with a timeout (5 minutes)
        cache_key = f'otp_{email}'
        cache.set(cache_key, otp, timeout=300)
        logger.debug(f"Stored OTP for {email} in cache: {otp}")  # Log the OTP

        # Verify OTP in cache (for debugging purposes)
        cached_otp = cache.get(cache_key)
        logger.debug(f"Cached OTP for {email} after setting: {cached_otp}")

        # Send OTP via email
        try:
            send_mail(
                'Your OTP Code',
                f'Your OTP code is {otp}',
                settings.DEFAULT_FROM_EMAIL,
                [email],
                fail_silently=False,
            )
            logger.info(f"Sent OTP to {email}")  # Log successful email sending
        except Exception as e:
            logger.error(f"Error sending email to {email}: {str(e)}")  # Log email errors
            return Response({"message": f"Error sending email: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response({"message": "OTP sent to email"}, status=status.HTTP_200_OK)


@api_view(['POST'])
def verify_otp(request):
    try:
        data = request.data
        email = data.get('user_email')
        otp = data.get('user_otp')
        print(email)
        print(otp)

        if isinstance(otp, list):
            otp = ''.join(otp) 
        print(otp, type(otp))

        logger.debug(f"Received email: {email}, otp: {otp}")

        if not email or not otp:
            return Response({'error': 'Email and OTP are required'}, status=400)

        # Retrieve OTP from cache
        cached_otp = cache.get(f'otp_{email}')
        logger.debug(f"Cached OTP for {email}: {cached_otp}")
        print(cached_otp, type(cached_otp))

        if cached_otp is None:
            return Response({'error': 'OTP has expired or not found'}, status=400)

        if cached_otp != otp:
            return Response({'error': 'Invalid OTP'}, status=400)
        
        if cached_otp == otp:
            cache.set(f'verified_email_{email}', email, timeout=3600)
            return Response({'success': "OTP verified successfully"}, status=200)

        # # OTP is valid; fetch user details
        # user = get_object_or_404(CustomUser, user_email=email)

        # # Log the user in
        # auth_login(request, user)

        # print(not request.session.session_key)

        # # Ensure session ID is created and available
        # if not request.session.session_key:
        #     request.session.create()  # Create a new session if it doesn't exist

        # session_id = request.session.session_key

        # # Set session expiry
        # request.session.set_expiry(timedelta(minutes=60))

    except Exception as e:
        logger.error(f"Error in verify_otp: {str(e)}")
        return Response({'error': 'An error occurred. Please try again.'}, status=500)
    
class RecreatePasscode(viewsets.ViewSet):
    def create(self, request):
        email = request.data.get('email')
        new_password = request.data.get('password')  # Get the new password from the request
        new_password1 = request.data.get('confirmPassword')

        # Retrieve cached email
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM users")
            rows = cursor.fetchall()

        # Fetch app_password records
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM app_password")
            row1 = cursor.fetchall()

        # Create lists to store user IDs and emails
        user_ids = []
        emails = []
        for i in rows:
            user_ids.append(i[0])  # Assuming the first column is user_id
            emails.append(i[1])     # Assuming the second column is email

        print(email)
        print(emails)
        print(user_ids)

        user_id = None
        
        if email in emails:
            index = emails.index(email)
            user_id = user_ids[index]

        if user_id is None:
            return Response({'error': 'User not found'}, status=404)

        # Hash the new password
        # hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())

        # Update the password in the app_password table
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    "UPDATE app_password SET password_creation = %s, retype_password = %s WHERE id = %s",
                    [new_password, new_password1, user_id]  # Reusing hashed_password
                )

            return Response({'success': f'Passcode for {email} updated successfully'}, status=200)
        except Exception as e:
            return Response({'error': str(e)})
        

class WalletAddress(viewsets.ViewSet):
    def list(self, request):
        user_id = request.query_params.get('userId') 
        data = request.data
        print(data)
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM crypto_wallet_table")
            rows = cursor.fetchall()
        
        user_id_list = []
        sui_address = []
        for i in rows:
            user_id_list.append(i[5])
            sui_address.append(i[-1])

        print(user_id)

        print(user_id_list)
        print(sui_address)

        index = 0

        if user_id in user_id_list:
            index = user_id_list.index(user_id)
            
        return JsonResponse({'status': f'{sui_address[index]}', 'message': 'Wallet Address'})

class FiatAddress(viewsets.ViewSet):
    def list(self, request):
        user_id = request.query_params.get('userId') 
        data = request.data
        print(data)
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM fiat_wallet")
            rows = cursor.fetchall()

        user_id_fiat = []
        fiat_address = []
        for i in rows:
            user_id_fiat.append(i[-1])
            fiat_address.append(i[3])
        index1 = 0

        if user_id in user_id_fiat:
            index1 = user_id_fiat.index(user_id)
            
        return JsonResponse({'status': f'{fiat_address[index1]}', 'message': 'Fiat Address'})


class UnlockAddress(viewsets.ViewSet):
    queryset = Password.objects.all()
    serializer_class = PasswordSerializer
    def create(self, request):
        user_id = request.data.get('userId') 
        unlock_password = request.data.get('unlock_password')
        print(unlock_password, user_id)
        
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM app_password")
            rows = cursor.fetchall()

        unlock_list = []
        unloct_pass = []
        for i in rows:
            unlock_list.append(i[0])
            unloct_pass.append(i[-1])

        if user_id in unlock_list:
            index1 = unlock_list.index(user_id)
            with connection.cursor() as cursor:
                cursor.execute(
                    "UPDATE app_password SET unlock_password = %s WHERE id = %s",
                    [unlock_password, user_id]  # Reusing hashed_password
                )

            return Response({"message": "Unlock Password created"}, status=status.HTTP_200_OK)
        else:
            return Response({"message": "User_id not found"})
        
class DeleteWalletAddress(viewsets.ViewSet):
    def list(self, request):
        user_id = request.query_params.get('userId') 
        data = request.data
        print(data)
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM crypto_wallet_table")
            rows = cursor.fetchall()
        
        user_id_list = []
        sui_address = []
        for i in rows:
            user_id_list.append(i[5])
            sui_address.append(i[-1])

        print(user_id)

        print(user_id_list)
        print(sui_address)

        index = 0

        if user_id in user_id_list:
            index = user_id_list.index(user_id)
            
            return JsonResponse({'status': f'{sui_address[index]}', 'message': 'Wallet Address'})
        else:
            return JsonResponse({'status': 'user_id not found'})
    
    def create(self, request):
        user_id = request.data.get('userId') 
        print(user_id)
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM crypto_wallet_table")
            rows = cursor.fetchall()

        user_id_list = []
        sui_address = []
        for i in rows:
            user_id_list.append(i[5])
            sui_address.append(i[-1])
        index1 = 0
        print(user_id, user_id_list)
        print(user_id in user_id_list)
        if user_id in user_id_list:
            index1 = user_id_list.index(user_id)
            with connection.cursor() as cursor:
                cursor.execute(
                    "DELETE FROM crypto_wallet_table WHERE user_id = %s",
                    [user_id] 
                )
            
            return JsonResponse({'status': 'Deleted', 'message': 'Deleted Successfully'},status=200)
        else:
            return JsonResponse({'status': 'error', 'message': 'user_id not found'},status=400)


class DeleteFiatAddress(viewsets.ViewSet):
    def list(self, request):
        user_id = request.query_params.get('userId') 
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM fiat_wallet")
            rows = cursor.fetchall()

        user_id_fiat = []
        fiat_address = []
        for i in rows:
            user_id_fiat.append(i[-1])
            fiat_address.append(i[3])
        index1 = 0

        if user_id in user_id_fiat:
            index2 = user_id_fiat.index(user_id)
            
            return JsonResponse({'status': f'{fiat_address[index2]}', 'message': 'Fiat Address'})
        else:
            return JsonResponse({'status': 'user_id not found'})
        
    def create(self, request):
        user_id = request.data.get('userId') 
        print(user_id)
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM fiat_wallet")
            rows = cursor.fetchall()

        user_id_fiat = []
        fiat_address = []
        
        for i in rows:
            user_id_fiat.append(i[-1])
            fiat_address.append(i[3])
        index1 = 0
        print(user_id, user_id_fiat)
        print(user_id in user_id_fiat)
        if user_id in user_id_fiat:
            index1 = user_id_fiat.index(user_id)
            with connection.cursor() as cursor:
                cursor.execute(
                    "DELETE FROM fiat_wallet WHERE user_id = %s",
                    [user_id] 
                )
            
            return JsonResponse({'status': 'Deleted', 'message': 'Deleted Successfully'},status=200)
        else:
            return JsonResponse({'status': 'error', 'message': 'user_id not found'},status=400)