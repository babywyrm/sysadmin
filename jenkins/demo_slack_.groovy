

##
#
https://stackoverflow.com/questions/39140191/how-to-send-slack-notification-after-a-jenkins-pipeline-build-failed
#
##

I have a pipeline groovy script in Jenkins v2.19. Also I have a
"Slack Notification Plugin" v2.0.1 and "Groovy Postbuild Plugin" installed.

I can successfully send "build started" and "build finished" messages.

When a build fails, how can I send the "Build failed" message to a Slack channel?

jenkinsgroovyjenkins-pipelineslack
Share
Improve this question
Follow
edited Sep 29, 2022 at 20:56
asked Aug 25, 2016 at 8:24
kivagant's user avatar
kivagant
1,80111 gold badge2222 silver badges3333 bronze badges
It seems to me the Slack plugin already has a "notify failure" checkbox. Do you use latest version of Slack plugin ? – 
Riduidel
 Aug 25, 2016 at 8:39
@Riduidel, where you can see this checkbox? – 
kivagant
 Aug 25, 2016 at 8:44
I have a 2.0.1 version of the Slack Notification Plugin – 
kivagant
 Aug 25, 2016 at 8:44
Checkbox is visible on Slack plugin website : wiki.jenkins-ci.org/display/JENKINS/Slack+Plugin (see section "Project Configuration") – 
Riduidel
 Aug 25, 2016 at 13:32
7
I have a Pipeline project: jenkins.io/doc/pipeline It's have different configuration an does not have this options at all. – 
kivagant
 Aug 25, 2016 at 14:12 
Add a comment
3 Answers
Sorted by:

Highest score (default)

45


You could do something like this and use a try catch block.

Here is some example Code:

node {
    try {
        notifyBuild('STARTED')

        stage('Prepare code') {
            echo 'do checkout stuff'
        }

        stage('Testing') {
            echo 'Testing'
            echo 'Testing - publish coverage results'
        }

        stage('Staging') {
            echo 'Deploy Stage'
        }

        stage('Deploy') {
            echo 'Deploy - Backend'
            echo 'Deploy - Frontend'
        }

  } catch (e) {
    // If there was an exception thrown, the build failed
    currentBuild.result = "FAILED"
    throw e
  } finally {
    // Success or failure, always send notifications
    notifyBuild(currentBuild.result)
  }
}

def notifyBuild(String buildStatus = 'STARTED') {
  // build status of null means successful
  buildStatus =  buildStatus ?: 'SUCCESSFUL'

  // Default values
  def colorName = 'RED'
  def colorCode = '#FF0000'
  def subject = "${buildStatus}: Job '${env.JOB_NAME} [${env.BUILD_NUMBER}]'"
  def summary = "${subject} (${env.BUILD_URL})"

  // Override default values based on build status
  if (buildStatus == 'STARTED') {
    color = 'YELLOW'
    colorCode = '#FFFF00'
  } else if (buildStatus == 'SUCCESSFUL') {
    color = 'GREEN'
    colorCode = '#00FF00'
  } else {
    color = 'RED'
    colorCode = '#FF0000'
  }

  // Send notifications
  slackSend (color: colorCode, message: summary)
}
Complete snippet can be found here Jenkinsfile Template

Share
Improve this answer
Follow
answered Oct 9, 2016 at 10:15
JamalMcCrackin's user avatar
JamalMcCrackin
6201010 silver badges1515 bronze badges
1
Thank you, @Fahl-Design, I'll try this a bit later and will write result to you. – 
kivagant
 Oct 10, 2016 at 7:05
Great! enjoy ;) As you can see in that snippet you can add any other notification service after slackSend – 
JamalMcCrackin
 Oct 12, 2016 at 8:38
1
I used your example. When I produce an exception the value buildStatus will be "FAILURE" instead of "FAILED". Why though? – 
agoldev
 Sep 5, 2019 at 22:53
Found out why. The assigned value is matched against possible values and if no match is possible "FAILURE" will be returned. See github.com/jenkinsci/jenkins/blob/master/core/src/main/java/… and github.com/jenkinsci/jenkins/blob/master/core/src/main/java/…. For consistency I would then assign "FAILURE" in the catch block. – 
agoldev
 Sep 6, 2019 at 7:15
2
The build status should be called SUCCESS, not SUCCESSFUL (at least in the recent Jenkins, when put in always/post block). – 
kenorb
 Nov 11, 2020 at 14:49 
Add a comment

35


Just in case if in Declarative Syntax,

Now, Jenkins provides post. You can check result at the end of pipeline.

https://jenkins.io/doc/book/pipeline/syntax/#post-example

Using like:

pipeline {
    stages { ... }
    post {
       // only triggered when blue or green sign
       success {
           slackSend ...
       }
       // triggered when red sign
       failure {
           slackSend ...
       }
       // trigger every-works
       always {
           slackSend ...
       }
    }
}
It would be used in every stage also. See the document link please.

Share
Improve this answer
Follow
edited Jun 22, 2018 at 8:09
answered May 28, 2018 at 22:28
Rakk's user avatar
Rakk
51144 silver badges88 bronze badges
3
It is important to note that the OP uses a Groovy (AKA scripted) pipeline, whereas post can only be used in a declarative pipeline. You cannot mix both. – 
beatngu13
 Jun 8, 2018 at 8:43
@beatngu13 Oh, yes, That is what I missed. Thank you – 
Rakk
 Jun 22, 2018 at 8:10
@Rakk - When I use success or failure I get an error Error when executing failure post condition: groovy.lang.MissingPropertyException: No such property: build for class: groovy.lang.Binding . I'm using this in declarative pipeline – 
Psdet
 Dec 9, 2019 at 2:01
@Prr I'm not sure but guessing you are using in build object. It is only be in pipeline object. – 
Rakk
 Dec 13, 2019 at 12:00
that is half backed as post usually has some clean up routine that may fail and you will not get to the slack call as it should be done after all activities. – 
Dmitry
 Oct 28, 2021 at 14:49
Show 1 more comment

29


Based on Liam Newman's blog post, have a look at this cleaned up snippet for Slack only in scripted pipelines (declarative pipeline users scroll down). It uses original Jenkins results, message formatting, better colors (based on EclEmma), and some Groovy features like default arguments:

def notifySlack(String buildStatus = 'STARTED') {
    // Build status of null means success.
    buildStatus = buildStatus ?: 'SUCCESS'

    def color

    if (buildStatus == 'STARTED') {
        color = '#D4DADF'
    } else if (buildStatus == 'SUCCESS') {
        color = '#BDFFC3'
    } else if (buildStatus == 'UNSTABLE') {
        color = '#FFFE89'
    } else {
        color = '#FF9FA1'
    }

    def msg = "${buildStatus}: `${env.JOB_NAME}` #${env.BUILD_NUMBER}:\n${env.BUILD_URL}"

    slackSend(color: color, message: msg)
}

node {
    try {
        notifySlack()

        // Existing build steps.
    } catch (e) {
        currentBuild.result = 'FAILURE'
        throw e
    } finally {
        notifySlack(currentBuild.result)
    }
}
