from django import views
from django.urls import path, include
from rest_framework.routers import DefaultRouter

from .views import NotificationViewSet
from .views import PasswordViewSet, RepasswordViewSet, LogPassword, LogPasswordLock, GenerateOTP, verify_otp, RecreatePasscode, WalletAddress, FiatAddress, UnlockAddress, DeleteFiatAddress, DeleteWalletAddress
from password import views

router = DefaultRouter()

router.register(r'notification', NotificationViewSet, basename='notification')
router.register(r'password', PasswordViewSet, basename='password')
router.register(r'repassword', RepasswordViewSet, basename='repassword')
router.register(r'logpassword', LogPassword, basename='logpassword')
router.register(r'logpassword1', LogPasswordLock, basename='logpassword1')
# router.register(r'verify_otp', verify_otp, basename='verify_otp')
router.register(r'recreatepasscode', RecreatePasscode, basename='recreatepasscode')
router.register(r'walletaddress', WalletAddress, basename='walletaddress')
router.register(r'fiataddress', FiatAddress, basename='fiataddress')
router.register(r'unlockpassword', UnlockAddress, basename='unlockpassword')
router.register(r'deletewalletaddress', DeleteWalletAddress, basename='deletewalletaddress')
router.register(r'deletefiataddress', DeleteFiatAddress, basename='deletefiataddress')



urlpatterns = [
    path('',include(router.urls)),
    path('generate_otp/', GenerateOTP.as_view(), name='generate_otp'),
    path('verify_otp/', verify_otp, name='verify_otp'),
    # path('profile/<pk>/', UserProfileView.as_view())
    
]