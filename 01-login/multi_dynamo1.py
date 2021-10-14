import boto3
import json

s=input("enter table name ")
dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table(s)

response = table.get_item(Key={'Organization': "CMIN"})
print(response['Item'])

# with open("data.json") as json_file:
#     records = json.load(json_file)
#     for nam in records:
#         organization = nam['Organization']
#         operatornum1 = int(nam['Operator num1'])
#         operatornum2 = int(nam['Operator num2'])
#         operatornum3 = int(nam['Operator num3'])
        
#         table.put_item(
#             Item={
#                     'Organization': organization,
#                     'Operator num1': operatornum1,
#                     'Operator num2': operatornum2,
#                     'Operator num3': operatornum3
#                 }
#             )