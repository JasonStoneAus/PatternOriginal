FROM circleci/ruby:2.7.5-node

RUN sudo gem update --system

RUN sudo gem install bundler

WORKDIR /workdir
ADD . ./

RUN echo '#!/usr/bin/env bash \n\
\n\
cd /workdir \n\
sudo bundle config --local path vendor/bundle \n\
sudo bundle install \n\
if [ -f _config-extras.yml ]; then \n\
    sudo JEKYLL_ENV=production bundle exec jekyll serve --port 80 --config _config.yml,_config-extras.yml -H 0.0.0.0 --watch --drafts --destination ./_site \n\
else \n\
    sudo JEKYLL_ENV=production bundle exec jekyll build && sudo JEKYLL_ENV=production bundle exec jekyll serve --port 80 -H 0.0.0.0 --watch --drafts --destination ./_site \n\
fi \n\
\n\
exec "$@"' > /tmp/start.sh

RUN chmod +x /tmp/start.sh

ENTRYPOINT ["/tmp/start.sh"]