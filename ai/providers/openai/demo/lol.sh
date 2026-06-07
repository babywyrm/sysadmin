# Source: https://gist.github.com/vfarcic/e79daf07ecdcb627e819b61aa851462d

#########################################################
# ow to Earn Billions With AI, ChatGPT, and Kubernetes? #
# https://youtu.be/1ak_O5HgKcM                          #
#########################################################

# Additional Info:
# - Cast AI: https://cast.ai/devopstoolkit

#########
# Setup #
#########

# Create a Kubernetes cluster (any should do).

git clone https://github.com/vfarcic/openai-demo

cd openai-demo

kubectl create namespace demo

kubectl --namespace demo apply --filename app.yaml

# Register at https://platform.openai.com

# Generate OpenAI API key

# Replace `[...]` with the OpenAI API key
OPENAI_KEY=[...]

# Install `jq` CLI from https://stedolan.github.io/jq/download/

chmod +x awesome-ai-*

# Install Go by following the instructions at
#   https://go.dev/doc/install

############
# The Idea #
############

kubectl --namespace demo get pods

# Replace `[...]` with the pod name
kubectl --namespace demo describe pod [...]

# Open https://chat.openai.com in a browser

#############################################
# Building an MVP and Requesting Seed Money #
#############################################

curl https://api.openai.com/v1/chat/completions \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $OPENAI_KEY" \
    -d '{
        "model": "gpt-3.5-turbo",
        "messages": [{
            "role": "user",
            "content": "Is Kubernetes awesome?"
        }]
    }'

curl https://api.openai.com/v1/chat/completions \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $OPENAI_KEY" \
    -d '{
        "model": "gpt-3.5-turbo",
        "messages": [{
            "role": "user",
            "content": "Is Kubernetes awesome?"
        }]
    }' | jq ".choices[0].message.content"

cat awesome-ai-v0.1.0

./awesome-ai-v0.1.0

###########################################################
# Building a "Real" Product and Requesting Series A Money #
###########################################################

export NAMESPACE=demo

kubectl --namespace $NAMESPACE get pods

# Replace `[...]` with the pod name
export POD=[...]

export EVENTS=$(kubectl --namespace $NAMESPACE get events \
    --field-selector involvedObject.name=$POD)

echo $EVENTS

export MESSAGE="Explain what's wrong with a Kubernetes pod that contains following events: $EVENTS"

export MESSAGE=$(echo $MESSAGE | tr '\n' ' ' | tr '"' ' ')

echo $MESSAGE

cat question-template.json

cat question-template.json \
    | jq ".messages[0].content = \"$MESSAGE\"" > question.json

cat question.json

curl https://api.openai.com/v1/chat/completions \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $OPENAI_KEY" \
    -d @question.json | jq ".choices[0].message.content"

cat awesome-ai-v1.0.0

./awesome-ai-v1.0.0 demo

#############################
# Requesting Series B Money #
#############################

cat main.go

go build -o awesome-ai-v2.0.0

chmod +x awesome-ai-v2.0.0

./awesome-ai-v2.0.0 --namespace demo

###########
# Destroy #
###########

# Destroy or reset the Kubernetes cluster
      
