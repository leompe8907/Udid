from rest_framework import serializers
from .models import ListOfSubscriber, ListOfSmartcards, SubscriberLoginInfo, SubscriberInfo

class SubscriberSerializer(serializers.ModelSerializer):
    class Meta:
        model = ListOfSubscriber
        fields = '__all__'

class ListOfSmartcardsSerializer(serializers.ModelSerializer):
    class Meta:
        model = ListOfSmartcards
        fields = '__all__'

class SubscriberLoginInfoSerializer(serializers.ModelSerializer):
    class Meta:
        model = SubscriberLoginInfo
        fields = '__all__'

class SubscriberLoginInfoSerializer(serializers.ModelSerializer):
    class Meta:
        model = SubscriberLoginInfo
        fields = '__all__'

class ListOfSubscriberSerializer(serializers.ModelSerializer):
    login_info = SubscriberLoginInfoSerializer(many=True, read_only=True)

    class Meta:
        model = ListOfSubscriber
        fields = '__all__'
