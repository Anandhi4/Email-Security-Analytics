import pandas as pd

# Read dataset
df = pd.read_csv("spam_email_dataset.csv")

# Function to classify threat
def classify_threat(row):
    # Malware
    if (
            #row['has_attachment'] == 1
            row['sender_reputation_score'] < 0.40
            #and row['num_links'] > 2
    ):
        return "Malware"

    # Phishing
    elif (
            row['has_suspicious_link'] == 1
            and row['contains_urgency_terms'] == 1
    ):
        return "Phishing"

    # BEC
    elif (
            row['contains_money_terms'] == 1
            and row['num_recipients'] <= 3
    ):
        return "BEC"

    # Spam
    elif (
            row['num_links'] > 5
    ):
        return "Spam"


# Create ThreatType column
df['ThreatType'] = df.apply(classify_threat, axis=1)


# Severity mapping
severity_map = {

    "No Threat": "Low",
    "Spam": "Medium",
    "Phishing": "High",
    "Malware": "Critical",
    "BEC": "Critical",
}


df['has_attachment'] = df['has_attachment'].map({
    1:"Yes",
    0:"No"
})

df['is_weekend'] = df['is_weekend'].map({
    1:"Yes",
    0:"No"
})

df['has_suspicious_link'] = df['has_suspicious_link'].map({
    1:"Yes",
    0:"No"
})

df['Severity'] = df['ThreatType'].map(severity_map)

# Action mapping
action_map = {

    "No Threat": "Delivered",
    "Spam": "Moved to Junk",
    "Phishing": "Quarantined",
    "Malware": "Blocked",
    "BEC": "Quarantined",
}

df['ActionTaken'] = df['ThreatType'].map(action_map)

#Adding new row Type instead of label
df['Type'] = df.apply(
    lambda row: 'Safe'
    if pd.isna(row['ThreatType']) and
       pd.isna(row['Severity']) and
       pd.isna(row['ActionTaken'])
    else 'Malicious',
    axis=1
)

#filling the Nan rows for Safe mails
df['ThreatType'] = df['ThreatType'].fillna('No Threat')
df['Severity'] = df['Severity'].fillna('Low')
df['ActionTaken'] = df['ActionTaken'].fillna('Delivered')

#Removing the label column
df.drop(columns =['email_id','label','num_exclamation_marks','has_attachment'], inplace= True)

df.rename(columns={
    'subject': 'Email Subject',
    'email_text': 'Email Content',
    'num_words': 'Word Count',
    'num_characters': 'Character Count',
    'num_exclamation_marks': 'Exclamation Count',
    'num_links': 'Link Count',
    'has_suspicious_link': 'Suspicious Link',
    'num_attachments': 'Attachment Count',
    'sender_email': 'Sender Email',
    'sender_domain': 'Sender Domain',
    'sender_reputation_score': 'Sender Reputation Score',
    'email_hour': 'Email Received Hour',
    'email_day_of_week': 'Email Received Day',
    'is_weekend': 'Received on Weekend',
    'num_recipients': 'Recipient Count',
    'contains_money_terms': 'Contains Money Terms',
    'contains_urgency_terms': 'Contains Urgency Terms',
    'ThreatType': 'Threat Type',
    'ActionTaken': 'Action Taken',
    'Type': 'Email Type'
}, inplace=True)

df['Contains Money Terms'] = df['Contains Money Terms'].map({
    1:"Yes",
    0:"No"
})

df['Contains Urgency Terms'] = df['Contains Urgency Terms'].map({
    1:"Yes",
    0:"No"
})

df['Email Received Day'] = df['Email Received Day'].map({
    0:"Monday",
    1:"Tuesday",
    2:"Wednesday",
    3:"Thursday",
    4:"Friday",
    5:"Saturday",
    6:"Sunday"
})

df = df[
    [
        'Email Subject',
        'Email Content',
        'Word Count',
        'Character Count',
         'Link Count',
         'Suspicious Link',
         'Attachment Count',
         'Sender Domain',
        'Sender Email',
         'Sender Reputation Score',
        'Email Received Hour',
         'Received on Weekend',
        'Email Received Day',
'Recipient Count',
    'Contains Money Terms', 'Contains Urgency Terms',
    'Threat Type',
        'Severity',
        'Action Taken',
        'Email Type'

    ]
]

# Save new dataset
df.to_csv("security_email_dataset.csv", index=False)

print("Dataset created successfully!")
print(df[['Threat Type','Severity','Action Taken']].head())